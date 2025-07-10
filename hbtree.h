#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#define HBTREE_FANOUT ((uint64_t) 512)

union hbtree_node {
    union hbtree_node *children[HBTREE_FANOUT];
    const void *leaf_data[HBTREE_FANOUT];
};

static_assert(sizeof(union hbtree_node) == 4096, "Size must be 4096");

struct hbtree {
    uint64_t top_width;
    union hbtree_node *top;
};

bool hbtree_init(struct hbtree *tree, uint8_t depth);
bool hbtree_insert(struct hbtree *tree, uint64_t key, const void *value);
const void *hbtree_get(const struct hbtree *tree, uint64_t key);
void hbtree_delete(struct hbtree *const tree, const uint64_t key);
void hbtree_cleanup(struct hbtree *tree);
void hbtree_walk(struct hbtree *tree, void (*cb)(uint64_t key, const void *value));
void hbtree_destroy(struct hbtree *tree, void (*dtor)(uint64_t key, const void *value));
