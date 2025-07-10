#include "hbtree.h"
#include "common.h"

#include <sys/mman.h>

static const void *leaf_to_insert;
static void (*callback_to_call)(uint64_t, const void *);
static const union hbtree_node zeroed_node __attribute__((aligned(4096)));

static inline union hbtree_node *alloc_node(void)
{
    void *const node = mmap(NULL, sizeof(union hbtree_node),
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (unlikely(node == MAP_FAILED)) {
        log_errno("Cannot allocate hbtree node");
        return NULL;
    }

    return node;
}

static inline bool free_node(union hbtree_node *const node)
{
    if (unlikely(munmap(node, sizeof(union hbtree_node)))) {
        log_errno("Cannot unmap hbtree node");
        return false;
    }

    return true;
}

static bool insert(union hbtree_node *const node, const uint64_t width, const uint64_t idx, const uint64_t key_offset)
{
    if (width == 1) {
        node->leaf_data[idx] = leaf_to_insert;
        return true;
    }

    if (!node->children[idx] && unlikely(!(node->children[idx] = alloc_node()))) {
        return false;
    }

    const uint64_t narrowed_width = width / HBTREE_FANOUT;
    return insert(node->children[idx], narrowed_width, key_offset / narrowed_width, key_offset % narrowed_width);
}

static const void *get(const union hbtree_node *const node, const uint64_t width, const uint64_t idx, const uint64_t key_offset)
{
    if (width == 1) {
        return node->leaf_data[idx];
    }

    if (node->children[idx]) {
        const uint64_t narrowed_width = width / HBTREE_FANOUT;
        return get(node->children[idx], narrowed_width, key_offset / narrowed_width, key_offset % narrowed_width);
    }

    return NULL;
}

static void delete(union hbtree_node *const node, const uint64_t width, const uint64_t idx, const uint64_t key_offset)
{
    if (width == 1) {
        node->leaf_data[idx] = NULL;
        return;
    }

    if (node->children[idx]) {
        const uint64_t narrowed_width = width / HBTREE_FANOUT;
        delete(node->children[idx], narrowed_width, key_offset / narrowed_width, key_offset % narrowed_width);
    }
}

static bool cleanup(union hbtree_node *const node, const uint64_t width)
{
    if (width == 1) {
        return !memcmp(node, &zeroed_node, sizeof(union hbtree_node));
    }

    bool all_zero = true;

    for (size_t idx = 0; idx < HBTREE_FANOUT; ++idx) {
        if (node->children[idx]) {
            if (cleanup(node->children[idx], width / HBTREE_FANOUT)) {
                if (likely(free_node(node->children[idx]))) {
                    node->children[idx] = NULL;
                } else {
                    all_zero = false;
                }
            } else {
                all_zero = false;
            }
        }
    }

    return all_zero;
}

static void walk(union hbtree_node *const node, const uint64_t width, const uint64_t key_base)
{
    if (width == 1) {
        for (size_t leaf_idx = 0; leaf_idx < HBTREE_FANOUT; ++leaf_idx) {
            if (node->leaf_data[leaf_idx]) {
                callback_to_call(key_base + leaf_idx, node->leaf_data[leaf_idx]);
            }
        }

        return;
    }

    for (size_t idx = 0; idx < HBTREE_FANOUT; ++idx) {
        if (node->children[idx]) {
            walk(node->children[idx], width / HBTREE_FANOUT, key_base + width * idx);
        }
    }
}

static bool destroy(union hbtree_node *const node, const uint64_t width, const uint64_t key_base)
{
    if (width == 1) {
        for (size_t leaf_idx = 0; leaf_idx < HBTREE_FANOUT; ++leaf_idx) {
            if (node->leaf_data[leaf_idx]) {
                if (callback_to_call) {
                    callback_to_call(key_base + leaf_idx, node->leaf_data[leaf_idx]);
                }

                node->leaf_data[leaf_idx] = NULL;
            }
        }

        return true;
    }

    bool all_zero = true;

    for (size_t idx = 0; idx < HBTREE_FANOUT; ++idx) {
        if (node->children[idx]) {
            if (destroy(node->children[idx], width / HBTREE_FANOUT, key_base + width * idx)) {
                if (likely(free_node(node->children[idx]))) {
                    node->children[idx] = NULL;
                } else {
                    all_zero = false;
                }
            } else {
                all_zero = false;
            }
        }
    }

    return all_zero;
}

bool hbtree_init(struct hbtree *const tree, const uint8_t depth)
{
    assert(depth >= 1 && depth <= 7);

    if (unlikely(!(tree->top = alloc_node()))) {
        return false;
    }

    tree->top_width = (const uint64_t []) {
        1,
        HBTREE_FANOUT,
        HBTREE_FANOUT * HBTREE_FANOUT,
        HBTREE_FANOUT * HBTREE_FANOUT * HBTREE_FANOUT,
        HBTREE_FANOUT * HBTREE_FANOUT * HBTREE_FANOUT * HBTREE_FANOUT,
        HBTREE_FANOUT * HBTREE_FANOUT * HBTREE_FANOUT * HBTREE_FANOUT * HBTREE_FANOUT,
        HBTREE_FANOUT * HBTREE_FANOUT * HBTREE_FANOUT * HBTREE_FANOUT * HBTREE_FANOUT * HBTREE_FANOUT,
    }[depth - 1];

    return true;
}

bool hbtree_insert(struct hbtree *const tree, const uint64_t key, const void *const value)
{
    assert(tree != NULL);
    assert(tree->top_width != 0);
    assert(tree->top != NULL);
    assert(key < tree->top_width * HBTREE_FANOUT);
    assert(value != NULL);

    leaf_to_insert = value;
    return insert(tree->top, tree->top_width, key / tree->top_width, key % tree->top_width);
}

const void *hbtree_get(const struct hbtree *const tree, const uint64_t key)
{
    assert(tree != NULL);
    assert(tree->top_width != 0);
    assert(tree->top != NULL);
    assert(key < tree->top_width * HBTREE_FANOUT);

    return get(tree->top, tree->top_width, key / tree->top_width, key % tree->top_width);
}

void hbtree_delete(struct hbtree *const tree, const uint64_t key)
{
    assert(tree != NULL);
    assert(tree->top_width != 0);
    assert(tree->top != NULL);
    assert(key < tree->top_width * HBTREE_FANOUT);

    delete(tree->top, tree->top_width, key / tree->top_width, key % tree->top_width);
}

void hbtree_cleanup(struct hbtree *tree)
{
    assert(tree != NULL);
    assert(tree->top_width != 0);
    assert(tree->top != NULL);

    cleanup(tree->top, tree->top_width);
}

void hbtree_walk(struct hbtree *tree, void (*const cb)(uint64_t, const void *))
{
    assert(tree != NULL);
    assert(tree->top_width != 0);
    assert(tree->top != NULL);
    assert(cb != NULL);

    callback_to_call = cb;
    walk(tree->top, tree->top_width, 0);
}

void hbtree_destroy(struct hbtree *tree, void (*const dtor)(uint64_t, const void *))
{
    assert(tree != NULL);
    assert(tree->top_width != 0);
    assert(tree->top != NULL);

    callback_to_call = dtor;

    if (destroy(tree->top, tree->top_width, 0) && likely(free_node(tree->top))) {
        tree->top = NULL;
    }
}
