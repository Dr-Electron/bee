// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{vertex::Vertex, MessageRef};

use bee_message::{Message, MessageId};

use async_rwlock::RwLock;
use async_trait::async_trait;
use dashmap::{mapref::entry::Entry, DashMap};
use log::info;
use lru::LruCache;

use std::{
    collections::HashSet,
    fmt::Debug,
    marker::PhantomData,
    ops::Deref,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
};

const CACHE_LEN: usize = 1_000_000;

/// A trait used to provide hooks for a tangle. The tangle acts as an in-memory cache and will use hooks to extend its
/// effective volume. When an entry doesn't exist in the tangle cache and needs fetching, or when an entry gets
/// inserted, the tangle will call out to the hooks in order to fulfil these actions.
#[async_trait]
pub trait Hooks<T> {
    /// An error generated by these hooks.
    type Error: Debug;

    /// Fetch a message from some external storage medium.
    async fn get(&self, message_id: &MessageId) -> Result<Option<(Message, T)>, Self::Error>;
    /// Insert a message into some external storage medium.
    async fn insert(&self, message_id: MessageId, tx: Message, metadata: T) -> Result<(), Self::Error>;
    /// Fetch the approvers list for a given message.
    async fn fetch_approvers(&self, message_id: &MessageId) -> Result<Option<Vec<MessageId>>, Self::Error>;
    /// Insert a new approver for a given message.
    async fn insert_approver(&self, message_id: MessageId, approver: MessageId) -> Result<(), Self::Error>;
    /// Update the approvers list for a given message.
    async fn update_approvers(&self, message_id: MessageId, approvers: &Vec<MessageId>) -> Result<(), Self::Error>;
}

/// Phoney default hooks that do nothing.
pub struct NullHooks<T>(PhantomData<T>);

impl<T> Default for NullHooks<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

#[async_trait]
impl<T: Send + Sync> Hooks<T> for NullHooks<T> {
    type Error = ();

    async fn get(&self, _message_id: &MessageId) -> Result<Option<(Message, T)>, Self::Error> {
        Ok(None)
    }

    async fn insert(&self, _message_id: MessageId, _tx: Message, _metadata: T) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn fetch_approvers(&self, _message_id: &MessageId) -> Result<Option<Vec<MessageId>>, Self::Error> {
        Ok(None)
    }

    async fn insert_approver(&self, _message_id: MessageId, _approver: MessageId) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn update_approvers(&self, _message_id: MessageId, _approvers: &Vec<MessageId>) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// A foundational, thread-safe graph datastructure to represent the IOTA Tangle.
pub struct Tangle<T, H = NullHooks<T>>
where
    T: Clone,
{
    // Global Tangle Lock. Remove this as and when it is deemed correct to do so.
    gtl: RwLock<()>,

    vertices: DashMap<MessageId, Vertex<T>>,
    children: DashMap<MessageId, (HashSet<MessageId>, bool)>,

    pub(crate) cache_counter: AtomicU64,
    pub(crate) cache_queue: Mutex<LruCache<MessageId, u64>>,

    pub(crate) hooks: H,
}

impl<T, H: Hooks<T>> Default for Tangle<T, H>
where
    T: Clone,
    H: Default,
{
    fn default() -> Self {
        Self::new(H::default())
    }
}

impl<T, H: Hooks<T>> Tangle<T, H>
where
    T: Clone,
{
    /// Creates a new Tangle.
    pub fn new(hooks: H) -> Self {
        Self {
            gtl: RwLock::new(()),

            vertices: DashMap::new(),
            children: DashMap::new(),

            cache_counter: AtomicU64::new(0),
            cache_queue: Mutex::new(LruCache::new(CACHE_LEN + 1)),

            hooks,
        }
    }

    /// Create a new tangle with the given capacity.
    pub fn with_capacity(self, cap: usize) -> Self {
        Self {
            cache_queue: Mutex::new(LruCache::new(cap + 1)),
            ..self
        }
    }

    /// Return a reference to the storage hooks used by this tangle.
    pub fn hooks(&self) -> &H {
        &self.hooks
    }

    async fn insert_inner(&self, message_id: MessageId, message: Message, metadata: T) -> Option<MessageRef> {
        let r = match self.vertices.entry(message_id) {
            Entry::Occupied(_) => None,
            Entry::Vacant(entry) => {
                self.add_child_inner(*message.parent1(), message_id).await;
                self.add_child_inner(*message.parent2(), message_id).await;
                let vtx = Vertex::new(message, metadata);
                let tx = vtx.message().clone();
                entry.insert(vtx);

                // Insert cache queue entry to track eviction priority
                self.cache_queue
                    .lock()
                    .unwrap()
                    .put(message_id, self.generate_cache_index());

                Some(tx)
            }
        };

        self.perform_eviction().await;

        r
    }

    /// Inserts a message, and returns a thread-safe reference to it in case it didn't already exist.
    pub async fn insert(&self, message_id: MessageId, message: Message, metadata: T) -> Option<MessageRef> {
        if self.contains_inner(&message_id) {
            None
        } else {
            let _gtl_guard = self.gtl.write().await;

            // Insert into backend using hooks
            self.hooks
                .insert(message_id, message.clone(), metadata.clone())
                .await
                .unwrap_or_else(|e| info!("Failed to insert message {:?}", e));

            self.insert_inner(message_id, message, metadata).await
        }
    }

    #[inline]
    async fn add_child_inner(&self, parent: MessageId, child: MessageId) {
        let mut children = self
            .children
            .entry(parent)
            .or_insert_with(|| (HashSet::default(), false));
        children.0.insert(child);
        self.hooks
            .insert_approver(parent, child)
            .await
            .unwrap_or_else(|e| info!("Failed to update approvers for message {:?}", e));
        // self.hooks
        // .update_approvers(parent, &children.iter().copied().collect::<Vec<_>>())
        // .await
        // .unwrap_or_else(|e| info!("Failed to update approvers for message message {:?}", e));
    }

    fn get_inner(&self, message_id: &MessageId) -> Option<impl Deref<Target = Vertex<T>> + '_> {
        self.vertices.get(message_id).map(|vtx| {
            let mut cache_queue = self.cache_queue.lock().unwrap();
            // Update message_id priority
            let entry = cache_queue.get_mut(message_id);
            let entry = if entry.is_none() {
                cache_queue.put(*message_id, 0);
                cache_queue.get_mut(message_id)
            } else {
                entry
            };
            *entry.unwrap() = self.generate_cache_index();

            vtx
        })
    }

    /// Get the data of a vertex associated with the given `message_id`.
    pub async fn get(&self, message_id: &MessageId) -> Option<MessageRef> {
        self.pull_message(message_id).await;

        self.get_inner(message_id).map(|v| v.message().clone())
    }

    fn contains_inner(&self, message_id: &MessageId) -> bool {
        self.vertices.contains_key(message_id)
    }

    /// Returns whether the message is stored in the Tangle.
    pub async fn contains(&self, message_id: &MessageId) -> bool {
        self.contains_inner(message_id) || self.pull_message(message_id).await
    }

    /// Get the metadata of a vertex associated with the given `message_id`.
    pub async fn get_metadata(&self, message_id: &MessageId) -> Option<T> {
        self.pull_message(message_id).await;

        self.get_inner(message_id).map(|v| v.metadata().clone())
    }

    /// Get the metadata of a vertex associated with the given `message_id`.
    pub async fn get_vertex(&self, message_id: &MessageId) -> Option<impl Deref<Target = Vertex<T>> + '_> {
        self.pull_message(message_id).await;

        self.get_inner(message_id)
    }

    /// Updates the metadata of a particular vertex.
    pub async fn set_metadata(&self, message_id: &MessageId, metadata: T) {
        self.pull_message(message_id).await;
        if let Some(mut vtx) = self.vertices.get_mut(message_id) {
            let _gtl_guard = self.gtl.write().await;

            *vtx.value_mut().metadata_mut() = metadata;
            self.hooks
                .insert(*message_id, (&**vtx.message()).clone(), vtx.metadata().clone())
                .await
                .unwrap_or_else(|e| info!("Failed to update metadata for message {:?}", e));
        }
    }

    /// Updates the metadata of a vertex.
    pub async fn update_metadata<Update>(&self, message_id: &MessageId, mut update: Update)
    where
        Update: FnMut(&mut T),
    {
        self.pull_message(message_id).await;
        if let Some(mut vtx) = self.vertices.get_mut(message_id) {
            let _gtl_guard = self.gtl.write().await;

            update(vtx.value_mut().metadata_mut());
            self.hooks
                .insert(*message_id, (&**vtx.message()).clone(), vtx.metadata().clone())
                .await
                .unwrap_or_else(|e| info!("Failed to update metadata for message {:?}", e));
        }
    }

    /// Returns the number of messages in the Tangle.
    pub fn len(&self) -> usize {
        // Does not take GTL because this is effectively atomic
        self.vertices.len()
    }

    /// Checks if the tangle is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    async fn children_inner(&self, message_id: &MessageId) -> Option<impl Deref<Target = HashSet<MessageId>> + '_> {
        struct Children<'a> {
            children: dashmap::mapref::one::Ref<'a, MessageId, (HashSet<MessageId>, bool)>,
        }

        impl<'a> Deref for Children<'a> {
            type Target = HashSet<MessageId>;

            fn deref(&self) -> &Self::Target {
                &self.children.deref().0
            }
        }

        let children = match self
            .children
            .get(message_id)
            // Skip approver lists that are not exhaustive
            .filter(|children| children.1)
        {
            Some(children) => children,
            None => {
                let _gtl_guard = self.gtl.write().await;

                self.hooks
                    .fetch_approvers(message_id)
                    .await
                    .unwrap_or_else(|e| {
                        info!("Failed to update approvers for message message {:?}", e);
                        None
                    })
                    .map(|approvers| {
                        self.children
                            .insert(*message_id, (approvers.into_iter().collect(), true))
                    });

                self.children
                    .get(message_id)
                    .expect("Approver list inserted and immediately evicted")
            }
        };

        Some(Children { children })
    }

    /// Returns the children of a vertex, if we know about them.
    pub async fn get_children(&self, message_id: &MessageId) -> Option<HashSet<MessageId>> {
        // Effectively atomic
        self.children_inner(message_id).await.map(|approvers| approvers.clone())
    }

    /// Returns the number of children of a vertex.
    pub async fn num_children(&self, message_id: &MessageId) -> usize {
        // Effectively atomic
        self.children_inner(message_id)
            .await
            .map_or(0, |approvers| approvers.len())
    }

    #[cfg(test)]
    pub fn clear(&mut self) {
        let _gtl_guard = self.gtl.write().await;

        self.vertices.clear();
        self.children.clear();
    }

    // Attempts to pull the message from the storage, returns true if successful.
    async fn pull_message(&self, message_id: &MessageId) -> bool {
        // If the tangle already contains the tx, do no more work
        if self.vertices.contains_key(message_id) {
            true
        } else {
            let _gtl_guard = self.gtl.write().await;

            if let Ok(Some((tx, metadata))) = self.hooks.get(message_id).await {
                self.insert_inner(*message_id, tx, metadata).await;
                true
            } else {
                false
            }
        }
    }

    fn generate_cache_index(&self) -> u64 {
        self.cache_counter.fetch_add(1, Ordering::Relaxed)
    }

    async fn perform_eviction(&self) {
        let mut cache = self.cache_queue.lock().unwrap();

        assert_eq!(cache.len(), self.len());

        if cache.len() == cache.cap() {
            let (message_id, _) = cache.pop_lru().expect("Cache capacity is zero");

            self.vertices
                .remove(&message_id)
                .expect("Expected vertex entry to exist");
            self.children.remove(&message_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bee_test::message::create_random_tx;
    use pollster::block_on;

    #[test]
    fn new_tangle() {
        let _: Tangle<u8> = Tangle::default();
    }

    #[test]
    fn insert_and_contains() {
        let tangle = Tangle::<()>::default();

        let (message_id, tx) = create_random_tx();

        let insert1 = block_on(tangle.insert(message_id, tx.clone(), ()));

        assert!(insert1.is_some());
        assert_eq!(1, tangle.len());
        assert!(block_on(tangle.contains(&message_id)));

        let insert2 = block_on(tangle.insert(message_id, tx, ()));

        assert!(insert2.is_none());
        assert_eq!(1, tangle.len());
        assert!(block_on(tangle.contains(&message_id)));
    }

    #[test]
    fn eviction_cap() {
        let tangle = Tangle::<()>::default().with_capacity(5);

        let txs = (0..10).map(|_| create_random_tx()).collect::<Vec<_>>();

        for (message_id, tx) in txs.iter() {
            let _ = block_on(tangle.insert(*message_id, tx.clone(), ()));
        }

        assert_eq!(tangle.len(), 5);
    }

    #[test]
    fn eviction_update() {
        let tangle = Tangle::<()>::default().with_capacity(5);

        let txs = (0..8).map(|_| create_random_tx()).collect::<Vec<_>>();

        for (message_id, tx) in txs.iter().take(4) {
            let _ = block_on(tangle.insert(*message_id, tx.clone(), ()));
        }

        assert!(block_on(tangle.get(&txs[0].0)).is_some());

        for (message_id, tx) in txs.iter().skip(4) {
            let _ = block_on(tangle.insert(*message_id, tx.clone(), ()));
        }

        assert!(block_on(tangle.contains(&txs[0].0)));

        for entry in tangle.vertices.iter() {
            assert!(entry.key() == &txs[0].0 || txs[4..].iter().any(|(h, _)| entry.key() == h));
        }
    }
}
