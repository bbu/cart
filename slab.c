#include "slab.h"
#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/mman.h>
#include <math.h>
#include <assert.h>

#define SLAB_DUMP_COLOURED

#ifdef SLAB_DUMP_COLOURED
# define GRAY(s)   "\033[1;30m" s "\033[0m"
# define RED(s)    "\033[0;31m" s "\033[0m"
# define GREEN(s)  "\033[0;32m" s "\033[0m"
# define YELLOW(s) "\033[1;33m" s "\033[0m"
#else
# define GRAY(s)   s
# define RED(s)    s
# define GREEN(s)  s
# define YELLOW(s) s
#endif

#define SLOTS_ALL_ZERO ((uint64_t) 0)
#define SLOTS_FIRST ((uint64_t) 1)

#define first_free_slot(slots) ((size_t) __builtin_ctzll(slots))
#define count_free_slots(slots) ((size_t) __builtin_popcountll(slots))

#define one_used_slot(slots, empty_slotmask) ({ \
    const typeof(slots) masked_slots = ~(slots) & (empty_slotmask); \
    (masked_slots & (masked_slots - 1)) == SLOTS_ALL_ZERO; \
})

size_t slab_pagesize = 4096;

#ifndef NDEBUG
static int slab_is_valid(const struct slab_chain *const sch)
{
    assert(powerof2(slab_pagesize));
    assert(powerof2(sch->slabsize));
    assert(powerof2(sch->pages_per_alloc));

    assert(sch->itemcount >= 2 && sch->itemcount <= 64);
    assert(sch->itemsize >= 1 && sch->itemsize <= SIZE_MAX);
    assert(sch->pages_per_alloc >= slab_pagesize);
    assert(sch->pages_per_alloc >= sch->slabsize);

    assert(offsetof(struct slab_header, data) + sch->itemsize * sch->itemcount <= sch->slabsize);

    assert(sch->empty_slotmask == ~SLOTS_ALL_ZERO >> (64 - sch->itemcount));
    assert(sch->initial_slotmask == (sch->empty_slotmask ^ SLOTS_FIRST));
    assert(sch->alignment_mask == ~(sch->slabsize - 1));

    const struct slab_header *const heads[] = { sch->full, sch->empty, sch->partial };

    for (size_t head = 0; head < countof(heads); ++head) {
        const struct slab_header *prev = NULL, *slab;

        for (slab = heads[head]; slab != NULL; slab = slab->next) {
            if (prev == NULL) {
                assert(slab->prev == NULL);
            } else {
                assert(slab->prev == prev);
            }

            switch (head) {
            case 0:
                assert(slab->slots == SLOTS_ALL_ZERO);
                break;

            case 1:
                assert(slab->slots == sch->empty_slotmask);
                break;

            case 2:
                assert((slab->slots & ~sch->empty_slotmask) == SLOTS_ALL_ZERO);
                assert(count_free_slots(slab->slots) >= 1);
                assert(count_free_slots(slab->slots) < sch->itemcount);
                break;
            }

            if (slab->refcount == 0) {
                assert((uintptr_t) slab % sch->slabsize == 0);

                if (sch->slabsize >= slab_pagesize) {
                    assert((uintptr_t) slab->page % sch->slabsize == 0);
                } else {
                    assert((uintptr_t) slab->page % slab_pagesize == 0);
                }
            } else {
                if (sch->slabsize >= slab_pagesize) {
                    assert((uintptr_t) slab % sch->slabsize == 0);
                } else {
                    assert((uintptr_t) slab % slab_pagesize == 0);
                }
            }

            prev = slab;
        }
    }

    return 1;
}
#endif

void slab_init(struct slab_chain *const sch, const size_t itemsize)
{
    assert(sch != NULL);
    assert(itemsize >= 1 && itemsize <= SIZE_MAX);
    assert(powerof2(slab_pagesize));

    sch->itemsize = itemsize;

    const size_t data_offset = offsetof(struct slab_header, data);
    const size_t least_slabsize = data_offset + 64 * sch->itemsize;
    sch->slabsize = (size_t) 1 << (size_t) ceil(log2(least_slabsize));
    sch->itemcount = 64;

    if (sch->slabsize - least_slabsize != 0) {
        const size_t shrinked_slabsize = sch->slabsize >> 1;

        if (data_offset < shrinked_slabsize &&
            shrinked_slabsize - data_offset >= 2 * sch->itemsize) {

            sch->slabsize = shrinked_slabsize;
            sch->itemcount = (shrinked_slabsize - data_offset) / sch->itemsize;
        }
    }

    sch->pages_per_alloc = sch->slabsize > slab_pagesize ? sch->slabsize : slab_pagesize;
    sch->empty_slotmask = ~SLOTS_ALL_ZERO >> (64 - sch->itemcount);
    sch->initial_slotmask = sch->empty_slotmask ^ SLOTS_FIRST;
    sch->alignment_mask = ~(sch->slabsize - 1);
    sch->partial = sch->empty = sch->full = NULL;

    assert(slab_is_valid(sch));
}

void *slab_alloc(struct slab_chain *const sch)
{
    assert(sch != NULL);
    assert(slab_is_valid(sch));

    if (likely(sch->partial != NULL)) {
        /* found a partial slab, locate the first free slot */
        register const size_t slot = first_free_slot(sch->partial->slots);
        sch->partial->slots ^= SLOTS_FIRST << slot;

        if (unlikely(sch->partial->slots == SLOTS_ALL_ZERO)) {
            /* slab has become full, change state from partial to full */
            struct slab_header *const tmp = sch->partial;

            /* skip first slab from partial list */
            if (likely((sch->partial = sch->partial->next) != NULL)) {
                sch->partial->prev = NULL;
            }

            if (likely((tmp->next = sch->full) != NULL)) {
                sch->full->prev = tmp;
            }

            sch->full = tmp;
            return sch->full->data + slot * sch->itemsize;
        } else {
            return sch->partial->data + slot * sch->itemsize;
        }
    } else if (likely((sch->partial = sch->empty) != NULL)) {
        /* found an empty slab, change state from empty to partial */
        if (likely((sch->empty = sch->empty->next) != NULL)) {
            sch->empty->prev = NULL;
        }

        sch->partial->next = NULL;

        /* slab is located either at the beginning of page, or beyond */
        if (unlikely(sch->partial->refcount != 0)) {
            sch->partial->refcount++;
        } else {
            sch->partial->page->refcount++;
        }

        sch->partial->slots = sch->initial_slotmask;
        return sch->partial->data;
    } else {
        /* no empty or partial slabs available, create a new one */
        if (sch->slabsize <= slab_pagesize) {
            sch->partial = mmap(NULL, sch->pages_per_alloc,
                PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

            if (unlikely(sch->partial == MAP_FAILED)) {
                log_errno("Cannot map slab memory area");
                return sch->partial = NULL;
            }
        } else {
            const int err = posix_memalign((void **) &sch->partial,
                sch->slabsize, sch->pages_per_alloc);

            if (unlikely(err)) {
                log_error("posix_memalign(align=%zu, size=%zu): %d\n",
                    sch->slabsize, sch->pages_per_alloc, err);

                return sch->partial = NULL;
            }
        }

        struct slab_header *prev = NULL;
        const char *const page_end = (char *) sch->partial + sch->pages_per_alloc;

        union {
            const char *c;
            struct slab_header *const s;
        } curr = {
            .c = (const char *) sch->partial + sch->slabsize
        };

        __builtin_prefetch(sch->partial, 1);

        sch->partial->prev = sch->partial->next = NULL;
        sch->partial->refcount = 1;
        sch->partial->slots = sch->initial_slotmask;

        if (likely(curr.c != page_end)) {
            curr.s->prev = NULL;
            curr.s->refcount = 0;
            curr.s->page = sch->partial;
            curr.s->slots = sch->empty_slotmask;
            sch->empty = prev = curr.s;

            while (likely((curr.c += sch->slabsize) != page_end)) {
                prev->next = curr.s;
                curr.s->prev = prev;
                curr.s->refcount = 0;
                curr.s->page = sch->partial;
                curr.s->slots = sch->empty_slotmask;
                prev = curr.s;
            }

            prev->next = NULL;
        }

        return sch->partial->data;
    }

    /* unreachable */
}

void slab_free(struct slab_chain *const sch, const void *const addr)
{
    assert(sch != NULL);
    assert(slab_is_valid(sch));
    assert(addr != NULL);

    struct slab_header *const slab = (void *) ((uintptr_t) addr & sch->alignment_mask);
    register const int slot = ((char *) addr - (char *) slab - offsetof(struct slab_header, data)) / sch->itemsize;

    if (unlikely(slab->slots == SLOTS_ALL_ZERO)) {
        /* target slab is full, change state to partial */
        slab->slots = SLOTS_FIRST << slot;

        if (likely(slab != sch->full)) {
            if (likely((slab->prev->next = slab->next) != NULL)) {
                slab->next->prev = slab->prev;
            }

            slab->prev = NULL;
        } else if (likely((sch->full = sch->full->next) != NULL)) {
            sch->full->prev = NULL;
        }

        slab->next = sch->partial;

        if (likely(sch->partial != NULL)) {
            sch->partial->prev = slab;
        }

        sch->partial = slab;
    } else if (unlikely(one_used_slot(slab->slots, sch->empty_slotmask))) {
        /* target slab is partial and has only one filled slot */
        if (unlikely(slab->refcount == 1 || (slab->refcount == 0 && slab->page->refcount == 1))) {
            /* unmap the whole page if this slab is the only partial one */
            if (likely(slab != sch->partial)) {
                if (likely((slab->prev->next = slab->next) != NULL)) {
                    slab->next->prev = slab->prev;
                }
            } else if (likely((sch->partial = sch->partial->next) != NULL)) {
                sch->partial->prev = NULL;
            }

            void *const page = unlikely(slab->refcount != 0) ? slab : slab->page;
            const char *const page_end = (char *) page + sch->pages_per_alloc;
            bool found_head = false;

            union {
                const char *c;
                const struct slab_header *const s;
            } s;

            for (s.c = page; s.c != page_end; s.c += sch->slabsize) {
                if (unlikely(s.s == sch->empty)) {
                    found_head = true;
                } else if (unlikely(s.s == slab)) {
                    continue;
                } else if (likely((s.s->prev->next = s.s->next) != NULL)) {
                    s.s->next->prev = s.s->prev;
                }
            }

            if (unlikely(found_head && (sch->empty = sch->empty->next) != NULL)) {
                sch->empty->prev = NULL;
            }

            if (sch->slabsize <= slab_pagesize) {
                if (unlikely(munmap(page, sch->pages_per_alloc))) {
                    log_errno("Cannot unmap slab memory area");
                }
            } else {
                free(page);
            }
        } else {
            slab->slots = sch->empty_slotmask;

            if (likely(slab != sch->partial)) {
                if (likely((slab->prev->next = slab->next) != NULL)) {
                    slab->next->prev = slab->prev;
                }

                slab->prev = NULL;
            } else if (likely((sch->partial = sch->partial->next) != NULL)) {
                sch->partial->prev = NULL;
            }

            slab->next = sch->empty;

            if (likely(sch->empty != NULL)) {
                sch->empty->prev = slab;
            }

            sch->empty = slab;

            if (unlikely(slab->refcount != 0)) {
                slab->refcount--;
            } else {
                slab->page->refcount--;
            }
        }
    } else {
        /* target slab is partial, no need to change state */
        slab->slots |= SLOTS_FIRST << slot;
    }
}

void slab_traverse(const struct slab_chain *const sch, void (*fn)(const void *))
{
    assert(sch != NULL);
    assert(fn != NULL);
    assert(slab_is_valid(sch));

    const struct slab_header *slab;
    const char *item, *end;
    const size_t data_offset = offsetof(struct slab_header, data);

    for (slab = sch->partial; slab; slab = slab->next) {
        item = (const char *) slab + data_offset;
        end = item + sch->itemcount * sch->itemsize;
        uint64_t mask = SLOTS_FIRST;

        do {
            if (!(slab->slots & mask)) {
                fn(item);
            }

            mask <<= 1;
        } while ((item += sch->itemsize) != end);
    }

    for (slab = sch->full; slab; slab = slab->next) {
        item = (const char *) slab + data_offset;
        end = item + sch->itemcount * sch->itemsize;

        do {
            fn(item);
        } while ((item += sch->itemsize) != end);
    }
}

void slab_destroy(const struct slab_chain *const sch)
{
    assert(sch != NULL);
    assert(slab_is_valid(sch));

    struct slab_header *const heads[] = { sch->partial, sch->empty, sch->full };
    struct slab_header *pages_head = NULL, *pages_tail;

    for (size_t i = 0; i < countof(heads); ++i) {
        struct slab_header *slab = heads[i];

        while (slab != NULL) {
            if (slab->refcount != 0) {
                struct slab_header *const page = slab;
                slab = slab->next;

                if (unlikely(pages_head == NULL)) {
                    pages_head = page;
                } else {
                    pages_tail->next = page;
                }

                pages_tail = page;
            } else {
                slab = slab->next;
            }
        }
    }

    if (likely(pages_head != NULL)) {
        pages_tail->next = NULL;
        struct slab_header *page = pages_head;

        if (sch->slabsize <= slab_pagesize) {
            do {
                void *const target = page;
                page = page->next;

                if (unlikely(munmap(target, sch->pages_per_alloc))) {
                    log_errno("Cannot unmap slab memory area");
                }
            } while (page != NULL);
        } else {
            do {
                void *const target = page;
                page = page->next;
                free(target);
            } while (page != NULL);
        }
    }
}

#ifndef NDEBUG
void slab_dump(FILE *const out, const struct slab_chain *const sch)
{
    assert(out != NULL);
    assert(sch != NULL);
    assert(slab_is_valid(sch));

    const struct slab_header *const heads[] = { sch->partial, sch->empty, sch->full };
    const char *labels[] = { "part", "empt", "full" };

    for (size_t i = 0; i < countof(heads); ++i) {
        const struct slab_header *slab = heads[i];

        fprintf(out,
            YELLOW("%6s ") GRAY("|%2d%13s|%2d%13s|%2d%13s|%2d%13s") "\n",
            labels[i], 64, "", 48, "", 32, "", 16, "");

        unsigned long long total = 0, row;

        for (row = 1; slab != NULL; slab = slab->next, ++row) {
            const unsigned used = sch->itemcount - count_free_slots(slab->slots);
            fprintf(out, GRAY("%6llu "), row);

            for (int k = 63; k >= 0; --k) {
                fprintf(out, slab->slots & (SLOTS_FIRST << k) ? GREEN("1") :
                    ((size_t) k >= sch->itemcount ? GRAY("0") : RED("0")));
            }

            fprintf(out, RED(" %8u") "\n", used);
            total += used;
        }

        fprintf(out,
            GREEN("%6s ") GRAY("^%15s^%15s^%15s^%15s") YELLOW(" %8llu") "\n\n",
            "", "", "", "", "", total);
    }
}

void slab_stats(FILE *const out, const struct slab_chain *const sch)
{
    assert(out != NULL);
    assert(sch != NULL);
    assert(slab_is_valid(sch));

    long long unsigned total_nr_slabs = 0, total_used_slots = 0, total_free_slots = 0;
    float occupancy;
    const struct slab_header *const heads[] = { sch->partial, sch->empty, sch->full };
    const char *labels[] = { "Partial", "Empty", "Full" };

    fprintf(out, "%8s %17s %17s %17s %17s\n", "",
        "Slabs", "Used", "Free", "Occupancy");

    for (size_t i = 0; i < countof(heads); ++i) {
        long long unsigned nr_slabs = 0, used_slots = 0, free_slots = 0;
        const struct slab_header *slab;

        for (slab = heads[i]; slab != NULL; slab = slab->next, nr_slabs++) {
            used_slots += sch->itemcount - count_free_slots(slab->slots);
            free_slots += count_free_slots(slab->slots);
        }

        occupancy = used_slots + free_slots ?
            100 * (float) used_slots / (used_slots + free_slots) : 0.0;

        fprintf(out, "%8s %17llu %17llu %17llu %16.2f%%\n",
            labels[i], nr_slabs, used_slots, free_slots, occupancy);

        total_nr_slabs += nr_slabs;
        total_used_slots += used_slots;
        total_free_slots += free_slots;
    }

    occupancy = total_used_slots + total_free_slots ?
        100 * (float) total_used_slots / (total_used_slots + total_free_slots) : 0.0;

    fprintf(out, "%8s %17llu %17llu %17llu %16.2f%%\n", "Total",
        total_nr_slabs, total_used_slots, total_free_slots, occupancy);
}

void slab_props(FILE *const out, const struct slab_chain *const sch)
{
    assert(out != NULL);
    assert(sch != NULL);
    assert(slab_is_valid(sch));

    fprintf(out,
        "%18s: %8zu\n"
        "%18s: %8zu = %.2f * (%zu pagesize)\n"
        "%18s: %8zu = (%zu offset) + (%zu itemcount) * (%zu itemsize)\n"
        "%18s: %8zu = (%zu slabsize) - (%zu total)\n"
        "%18s: %8zu = %zu * (%zu pagesize)\n"
        "%18s: %8zu = (%zu alloc) / (%zu slabsize)\n",

        "pagesize",
            slab_pagesize,

        "slabsize",
            sch->slabsize, (float) sch->slabsize / slab_pagesize, slab_pagesize,

        "total",
            offsetof(struct slab_header, data) + sch->itemcount * sch->itemsize,
            offsetof(struct slab_header, data), sch->itemcount, sch->itemsize,

        "waste per slab",
            sch->slabsize - offsetof(struct slab_header, data) -
            sch->itemcount * sch->itemsize, sch->slabsize,
            offsetof(struct slab_header, data) + sch->itemcount * sch->itemsize,

        "pages per alloc",
            sch->pages_per_alloc, sch->pages_per_alloc / slab_pagesize,
            slab_pagesize,

        "slabs per alloc",
            sch->pages_per_alloc / sch->slabsize, sch->pages_per_alloc,
            sch->slabsize
    );
}
#endif
