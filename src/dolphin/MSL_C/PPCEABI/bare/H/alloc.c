#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/alloc.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/ansi_files.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/critical_regions.h"
#include "string.h"

typedef struct Block {
    struct Block* prev;
    struct Block* next;
    unsigned long max_size;
    unsigned long size;
} Block;

typedef struct SubBlock {
    unsigned long size;
    Block* block;
    struct SubBlock* prev;
    struct SubBlock* next;
} SubBlock;

struct FixSubBlock;

typedef struct FixBlock {
    struct FixBlock* prev_;
    struct FixBlock* next_;
    unsigned long client_size_;
    struct FixSubBlock* start_;
    unsigned long n_allocated_;
} FixBlock;

typedef struct FixSubBlock {
    FixBlock* block_;
    struct FixSubBlock* next_;
} FixSubBlock;

typedef struct FixStart {
    FixBlock* tail_;
    FixBlock* head_;
} FixStart;

typedef struct __mem_pool_obj {
    Block* start_;
    FixStart fix_start[6];
} __mem_pool_obj;

typedef struct __mem_pool {
    void* reserved[14];
} __mem_pool;

typedef long tag_word;

typedef struct block_header {
    tag_word tag;
    struct block_header* prev;
    struct block_header* next;
} block_header;

typedef struct list_header {
    block_header* rover;
    block_header header;
} list_header;

typedef struct heap_header {
    struct heap_header* prev;
    struct heap_header* next;
} heap_header;

struct mem_pool_obj;
typedef void* (*sys_alloc_ptr)(unsigned long, struct mem_pool_obj*);
typedef void (*sys_free_ptr)(void*, struct mem_pool_obj*);

typedef struct pool_options {
    sys_alloc_ptr sys_alloc_func;
    sys_free_ptr sys_free_func;
    unsigned long min_heap_size;
    int always_search_first;
} pool_options;

typedef struct mem_pool_obj {
    list_header free_list;
    pool_options options;
    heap_header* heap_list;
    void* userData;

} mem_pool_obj;

static int initialized = 0;

static SubBlock* SubBlock_merge_prev(SubBlock*, SubBlock**);
static void SubBlock_merge_next(SubBlock*, SubBlock**);
static Block* link_new_block(__mem_pool_obj* pool_obj, unsigned long size);
static void Block_construct(Block* block, unsigned long size);
static SubBlock* Block_subBlock(Block* block, unsigned long requested_size);
static void* allocate_from_var_pools(__mem_pool_obj* pool_obj, unsigned long size);
static void* soft_allocate_from_var_pools(__mem_pool_obj* pool_obj, unsigned long size, unsigned long* available_size);
static void deallocate_from_var_pools(__mem_pool_obj* pool_obj, void* ptr);
static void* allocate_from_fixed_pools(__mem_pool_obj* pool_obj, unsigned long size);
static void deallocate_from_fixed_pools(__mem_pool_obj* pool_obj, void* ptr, unsigned long size);

static const unsigned long fix_pool_sizes[] = {4, 12, 20, 36, 52, 68};

#define SubBlock_size(ths) ((ths)->size & 0xFFFFFFF8)
#define SubBlock_block(ths) ((Block*)((unsigned long)((ths)->block) & ~0x1))
#define Block_size(ths) ((ths)->size & 0xFFFFFFF8)
#define Block_start(ths) (*(SubBlock**)((char*)(ths) + Block_size((ths)) - sizeof(unsigned long)))

#define SubBlock_set_free(ths) do {                                                                \
    unsigned long this_size = SubBlock_size((ths));                                                \
    (ths)->size &= ~0x2;                                                                           \
    *(unsigned long*)((char*)(ths) + this_size) &= ~0x4;                                           \
    *(unsigned long*)((char*)(ths) + this_size - sizeof(unsigned long)) = this_size;               \
} while(0)

#define SubBlock_is_free(ths) !((ths)->size & 2)
#define SubBlock_set_size(ths, sz) do {                                                            \
    (ths)->size &= ~0xFFFFFFF8;                                                                    \
    (ths)->size |= (sz) & 0xFFFFFFF8;                                                              \
    if (SubBlock_is_free((ths)))                                                                   \
        *(unsigned long*)((char*)(ths) + (sz) - sizeof(unsigned long)) = (sz);                    \
} while(0)

#define SubBlock_from_pointer(ptr) ((SubBlock*)((char*)(ptr)-8))
#define FixSubBlock_from_pointer(ptr) ((FixSubBlock*)((char*)(ptr)-4))

#define FixBlock_client_size(ths) ((ths)->client_size_)
#define FixSubBlock_size(ths) (FixBlock_client_size((ths)->block_))

#define classify(ptr) (*(unsigned long*)((char*)(ptr) - sizeof(unsigned long)) & 1)
#define __msize_inline(ptr)                                                                        \
    (!classify(ptr) ? FixSubBlock_size(FixSubBlock_from_pointer(ptr)) :                            \
                      SubBlock_size(SubBlock_from_pointer(ptr)) - 8)

#define Block_empty(ths)                                                                           \
    (_sb = (SubBlock*)((char*)(ths) + 16)),                                                        \
        SubBlock_is_free(_sb) && SubBlock_size(_sb) == Block_size((ths)) - 24

void __sys_free(void*);
void* __sys_alloc(unsigned long size);

static inline SubBlock* SubBlock_merge_prev(SubBlock* ths, SubBlock** start) {
    unsigned long prevsz;
    SubBlock* p;

    if (!(ths->size & 0x04)) {
        prevsz = *(unsigned long*)((char*)ths - sizeof(unsigned long));
        if (prevsz & 0x2)
            return ths;
        p = (SubBlock*)((char*)ths - prevsz);
        SubBlock_set_size(p, prevsz + SubBlock_size(ths));

        if (*start == ths)
            *start = (*start)->next;
        ths->next->prev = ths->prev;
        ths->next->prev->next = ths->next;
        return p;
    }
    return ths;
}

static asm void SubBlock_merge_next(SubBlock* pBlock, SubBlock** pStart) {
    nofralloc
    lwz r6, 0x0(r3)
    clrrwi r8, r6, 3
    add r5, r3, r8
    lwz r7, 0x0(r5)
    rlwinm. r0, r7, 0, 30, 30
    bnelr
    clrlwi r0, r6, 29
    clrrwi r6, r7, 3
    stw r0, 0x0(r3)
    add r7, r8, r6
    clrrwi r0, r7, 3
    lwz r6, 0x0(r3)
    or r0, r6, r0
    stw r0, 0x0(r3)
    lwz r0, 0x0(r3)
    rlwinm. r0, r0, 0, 30, 30
    bne _smn_1
    subi r0, r7, 0x4
    stwx r7, r3, r0
_smn_1:
    lwz r0, 0x0(r3)
    rlwinm. r0, r0, 0, 30, 30
    bne _smn_2
    lwzx r6, r3, r7
    li r0, -0x5
    and r0, r6, r0
    stwx r0, r3, r7
    b _smn_3
_smn_2:
    lwzx r0, r3, r7
    ori r0, r0, 0x4
    stwx r0, r3, r7
_smn_3:
    lwz r3, 0x0(r4)
    cmplw r3, r5
    bne _smn_4
    lwz r0, 0xc(r3)
    stw r0, 0x0(r4)
_smn_4:
    lwz r0, 0x0(r4)
    cmplw r0, r5
    bne _smn_5
    li r0, 0x0
    stw r0, 0x0(r4)
_smn_5:
    lwz r0, 0x8(r5)
    lwz r3, 0xc(r5)
    stw r0, 0x8(r3)
    lwz r0, 0xc(r5)
    lwz r3, 0x8(r5)
    stw r0, 0xc(r3)
    blr
}

asm void Block_link(Block* ths, SubBlock* sb) {
	nofralloc
	stwu r1, -0x10(r1)
	mflr r0
	li r5, -0x3
	stw r0, 0x14(r1)
	li r0, -0x5
	stw r31, 0xc(r1)
	stw r30, 0x8(r1)
	mr r30, r3
	lwz r6, 0x0(r4)
	and r3, r6, r5
	clrrwi r6, r6, 3
	stw r3, 0x0(r4)
	add r5, r4, r6
	lwz r3, 0x0(r5)
	and r0, r3, r0
	stw r0, 0x0(r5)
	stw r6, -0x4(r5)
	lwz r0, 0xc(r30)
	clrrwi r3, r0, 3
	subi r31, r3, 0x4
	add r31, r30, r31
	lwz r3, 0x0(r31)
	cmplwi r3, 0x0
	beq _bl_5
	lwz r0, 0x8(r3)
	stw r0, 0x8(r4)
	lwz r3, 0x8(r4)
	stw r4, 0xc(r3)
	lwz r0, 0x0(r31)
	stw r0, 0xc(r4)
	lwz r3, 0x0(r31)
	stw r4, 0x8(r3)
	stw r4, 0x0(r31)
	lwz r6, 0x0(r31)
	lwz r0, 0x0(r6)
	rlwinm. r0, r0, 0, 29, 29
	bne _bl_3
	lwz r5, -0x4(r6)
	rlwinm. r0, r5, 0, 30, 30
	beq _bl_0
	mr r4, r6
	b _bl_4
_bl_0:
	subf r4, r5, r6
	lwz r0, 0x0(r4)
	clrlwi r0, r0, 29
	stw r0, 0x0(r4)
	lwz r0, 0x0(r6)
	lwz r3, 0x0(r4)
	clrrwi r0, r0, 3
	add r0, r5, r0
	clrrwi r0, r0, 3
	or r0, r3, r0
	stw r0, 0x0(r4)
	lwz r0, 0x0(r4)
	rlwinm. r0, r0, 0, 30, 30
	bne _bl_1
	lwz r0, 0x0(r6)
	clrrwi r0, r0, 3
	add r3, r5, r0
	subi r0, r3, 0x4
	stwx r3, r4, r0
_bl_1:
	lwz r3, 0x0(r31)
	cmplw r3, r6
	bne _bl_2
	lwz r0, 0xc(r3)
	stw r0, 0x0(r31)
_bl_2:
	lwz r0, 0x8(r6)
	lwz r3, 0xc(r6)
	stw r0, 0x8(r3)
	lwz r5, 0xc(r6)
	lwz r3, 0x8(r5)
	stw r5, 0xc(r3)
	b _bl_4
_bl_3:
	mr r4, r6
_bl_4:
	stw r4, 0x0(r31)
	mr r4, r31
	lwz r3, 0x0(r31)
	bl SubBlock_merge_next
	b _bl_6
_bl_5:
	stw r4, 0x0(r31)
	stw r4, 0x8(r4)
	stw r4, 0xc(r4)
_bl_6:
	lwz r3, 0x0(r31)
	lwz r4, 0x8(r30)
	lwz r0, 0x0(r3)
	clrrwi r0, r0, 3
	cmplw r4, r0
	bge _bl_7
	stw r0, 0x8(r30)
_bl_7:
	lwz r0, 0x14(r1)
	lwz r31, 0xc(r1)
	lwz r30, 0x8(r1)
	mtlr r0
	addi r1, r1, 0x10
	blr
}

static inline Block* __unlink(__mem_pool_obj* pool_obj, Block* bp) {
    Block* result = bp->next;
    if (result == bp) {
        result = 0;
    }

    if (pool_obj->start_ == bp) {
        pool_obj->start_ = result;
    }

    if (result != 0) {
        result->prev = bp->prev;
        result->prev->next = result;
    }

    bp->next = 0;
    bp->prev = 0;
    return result;
}

inline void __init_pool_obj(__mem_pool* pool_obj) {
    memset(pool_obj, 0, sizeof(__mem_pool_obj));
}

static __mem_pool protopool_803DB818;
static unsigned char init_803DF080 = 0;

static inline __mem_pool* get_malloc_pool(void) {
    if (!init_803DF080) {
        __init_pool_obj(&protopool_803DB818);
        init_803DF080 = 1;
    }

    return &protopool_803DB818;
}

static void Block_construct(Block* block, unsigned long size) {
    SubBlock* sb;

    block->size = size | 3;
    *(unsigned long*)((char*)block + size - 8) = block->size;
    sb = (SubBlock*)((char*)block + 16);
    sb->block = (Block*)((unsigned long)block | 1);
    size -= 24;
    sb->size = size;
    *(unsigned long*)((char*)sb + size - sizeof(unsigned long)) = size;
    block->max_size = size;
    *(SubBlock**)((char*)block + (block->size & 0xFFFFFFF8UL) - 4) = 0;
    Block_link(block, sb);
}

extern const unsigned long lbl_802C3180[6];
extern void fn_80286F20(void*);

static asm SubBlock* Block_subBlock(Block* block, unsigned long requested_size) {
    nofralloc
    stwu r1, -0x10(r1)
    mflr r0
    lis r6, lbl_802C3180@ha
    stw r0, 0x14(r1)
    stw r31, 0xc(r1)
    mr r31, r3
    addi r3, r6, lbl_802C3180@l
    li r6, 0x0
    stw r30, 0x8(r1)
    b _bsb_1
_bsb_0:
    addi r3, r3, 0x4
    addi r6, r6, 0x1
_bsb_1:
    lwz r0, 0x0(r3)
    cmplw r5, r0
    bgt _bsb_0
    subi r7, r4, 0x4
    slwi r4, r6, 3
    lwz r3, 0x0(r7)
    addi r4, r4, 0x4
    add r4, r31, r4
    lwz r0, 0xc(r3)
    cmplwi r0, 0x0
    bne _bsb_3
    lwz r5, 0x4(r4)
    cmplw r5, r3
    beq _bsb_3
    lwz r0, 0x0(r4)
    cmplw r0, r3
    bne _bsb_2
    lwz r0, 0x0(r5)
    stw r0, 0x4(r4)
    lwz r5, 0x0(r4)
    lwz r0, 0x0(r5)
    stw r0, 0x0(r4)
    b _bsb_3
_bsb_2:
    lwz r0, 0x4(r3)
    lwz r5, 0x0(r3)
    stw r0, 0x4(r5)
    lwz r0, 0x0(r3)
    lwz r5, 0x4(r3)
    stw r0, 0x0(r5)
    lwz r0, 0x4(r4)
    stw r0, 0x4(r3)
    lwz r5, 0x4(r3)
    lwz r0, 0x0(r5)
    stw r0, 0x0(r3)
    lwz r5, 0x0(r3)
    stw r3, 0x4(r5)
    lwz r5, 0x4(r3)
    stw r3, 0x0(r5)
    stw r3, 0x4(r4)
_bsb_3:
    lwz r0, 0xc(r3)
    stw r0, 0x4(r7)
    stw r7, 0xc(r3)
    lwz r5, 0x10(r3)
    subic. r0, r5, 0x1
    stw r0, 0x10(r3)
    bne _bsb_12
    lwz r0, 0x4(r4)
    cmplw r0, r3
    bne _bsb_4
    lwz r0, 0x4(r3)
    stw r0, 0x4(r4)
_bsb_4:
    lwz r0, 0x0(r4)
    cmplw r0, r3
    bne _bsb_5
    lwz r0, 0x0(r3)
    stw r0, 0x0(r4)
_bsb_5:
    lwz r0, 0x4(r3)
    lwz r5, 0x0(r3)
    stw r0, 0x4(r5)
    lwz r0, 0x0(r3)
    lwz r5, 0x4(r3)
    stw r0, 0x0(r5)
    lwz r0, 0x4(r4)
    cmplw r0, r3
    bne _bsb_6
    li r0, 0x0
    stw r0, 0x4(r4)
_bsb_6:
    lwz r0, 0x0(r4)
    cmplw r0, r3
    bne _bsb_7
    li r0, 0x0
    stw r0, 0x0(r4)
_bsb_7:
    lwz r0, -0x4(r3)
    subi r4, r3, 0x8
    clrrwi r30, r0, 1
    mr r3, r30
    bl Block_link
    lwz r3, 0x10(r30)
    li r5, 0x0
    rlwinm. r0, r3, 0, 30, 30
    bne _bsb_8
    lwz r0, 0xc(r30)
    clrrwi r4, r3, 3
    clrrwi r3, r0, 3
    subi r0, r3, 0x18
    cmplw r4, r0
    bne _bsb_8
    li r5, 0x1
_bsb_8:
    cmpwi r5, 0x0
    beq _bsb_12
    lwz r4, 0x4(r30)
    cmplw r4, r30
    bne _bsb_9
    li r4, 0x0
_bsb_9:
    lwz r0, 0x0(r31)
    cmplw r0, r30
    bne _bsb_10
    stw r4, 0x0(r31)
_bsb_10:
    cmplwi r4, 0x0
    beq _bsb_11
    lwz r0, 0x0(r30)
    stw r0, 0x0(r4)
    lwz r3, 0x0(r4)
    stw r4, 0x4(r3)
_bsb_11:
    li r0, 0x0
    mr r3, r30
    stw r0, 0x4(r30)
    stw r0, 0x0(r30)
    bl fn_80286F20
_bsb_12:
    lwz r0, 0x14(r1)
    lwz r31, 0xc(r1)
    lwz r30, 0x8(r1)
    mtlr r0
    addi r1, r1, 0x10
    blr
}

static Block* link_new_block(__mem_pool_obj* pool_obj, unsigned long size) {
    Block* block;
    unsigned long aligned_size;

    aligned_size = (size + 0x1FUL) & 0xFFFFFFF8;
    if (aligned_size < 0x10000) {
        aligned_size = 0x10000;
    }

    block = (Block*)__sys_alloc(aligned_size);
    if (block == 0) {
        return 0;
    }

    Block_construct(block, aligned_size);
    if (pool_obj->start_ != 0) {
        block->prev = pool_obj->start_->prev;
        block->prev->next = block;
        block->next = pool_obj->start_;
        pool_obj->start_->prev = block;
        pool_obj->start_ = block;
    } else {
        pool_obj->start_ = block;
        block->prev = block;
        block->next = block;
    }
    return block;
}

static void* allocate_from_var_pools(__mem_pool_obj* pool_obj, unsigned long size) {
    Block* block;
    Block* current_block;
    void* result;
    unsigned long aligned_size;

    aligned_size = (size + 0xFUL) & 0xFFFFFFF8UL;
    if (aligned_size < 0x50UL) {
        aligned_size = 0x50UL;
    }

    if (pool_obj->start_ != 0) {
        block = pool_obj->start_;
    } else {
        block = link_new_block(pool_obj, aligned_size);
    }

    current_block = block;
    if (current_block == 0) {
        result = 0;
    } else {
        do {
            if ((aligned_size <= current_block->max_size) &&
                ((result = Block_subBlock(current_block, aligned_size)) != 0)) {
                pool_obj->start_ = current_block;
                goto done;
            }
            current_block = current_block->next;
        } while (current_block != pool_obj->start_);

        current_block = link_new_block(pool_obj, aligned_size);
        if (current_block == 0) {
            result = 0;
        } else {
            result = Block_subBlock(current_block, aligned_size);
done:
            result = (char*)result + 8;
        }
    }

    return result;
}

static void* soft_allocate_from_var_pools(__mem_pool_obj* pool_obj, unsigned long size, unsigned long* available_size) {
    Block* current_block;
    SubBlock* result;

    size = (size + 0xFU) & 0xFFFFFFF8;
    if (size < 0x50) {
        size = 0x50;
    }
    *available_size = 0;
    current_block = pool_obj->start_;
    if (current_block == 0) {
        return 0;
    }

    do {
        if (size <= current_block->max_size) {
            result = Block_subBlock(current_block, size);
            if (result != 0) {
                pool_obj->start_ = current_block;
                goto found;
            }
        }
        if ((8 < current_block->max_size) && (*available_size < current_block->max_size - 8)) {
            *available_size = current_block->max_size - 8;
        }
        current_block = current_block->next;
    } while (current_block != pool_obj->start_);

    return 0;
found:
    return (char*)result + 8;
}

static void deallocate_from_var_pools(__mem_pool_obj* pool_obj, void* ptr) {
    SubBlock* sb = SubBlock_from_pointer(ptr);
    SubBlock* _sb;

    Block* bp = SubBlock_block(sb);
    Block_link(bp, sb);

    if (Block_empty(bp)) {
        __unlink(pool_obj, bp);
        __sys_free(bp);
    }
}

static void* allocate_from_fixed_pools(__mem_pool_obj* pool_obj, unsigned long size) {
    unsigned long i = 0;
    FixStart* fs;

    while (size > fix_pool_sizes[i]) {
        ++i;
    }

    fs = &pool_obj->fix_start[i];

    if ((fs->head_ == 0) || (fs->head_->start_ == 0)) {
        const unsigned long* pool_sizes = fix_pool_sizes;
        unsigned long n = 0xFEC / (pool_sizes[i] + 4);
        unsigned long max_n;
        void* block;
        unsigned long max_free_size;
        unsigned long msize;
        unsigned long fix_size;
        unsigned long sub_size;
        unsigned long num_subblocks;
        FixBlock* b;
        FixBlock* head;
        FixBlock* tail;
        FixSubBlock* p;
        unsigned long k;

        if (n > 0x100) {
            n = 0x100;
        }

        max_n = n;

        while (n >= 10) {
            block = soft_allocate_from_var_pools(pool_obj, n * (pool_sizes[i] + 4) + 0x14, &max_free_size);
            if (block != 0) {
                break;
            }

            if (max_free_size > 0x14) {
                n = (max_free_size - 0x14) / (pool_sizes[i] + 4);
            } else {
                n = 0;
            }
        }

        if ((block == 0) && (n < max_n)) {
            block = allocate_from_var_pools(pool_obj, max_n * (pool_sizes[i] + 4) + 0x14);
            if (block == 0) {
                return 0;
            }
        }

        msize = __msize_inline(block);

        if (fs->head_ == 0) {
            fs->head_ = (FixBlock*)block;
            fs->tail_ = (FixBlock*)block;
        }

        fix_size = pool_sizes[i];
        sub_size = fix_size + 4;
        b = (FixBlock*)block;
        head = fs->head_;
        tail = fs->tail_;
        num_subblocks = (msize - 0x14) / sub_size;
        p = (FixSubBlock*)((char*)b + 0x14);
        b->prev_ = tail;
        b->next_ = head;
        tail->next_ = b;
        head->prev_ = b;
        b->client_size_ = fix_size;

        {
            char* cp = (char*)p;
            char* np;
            for (k = 0; k < num_subblocks - 1; ++k) {
                np = cp + sub_size;
                ((FixSubBlock*)cp)->block_ = b;
                ((FixSubBlock*)cp)->next_ = (FixSubBlock*)np;
                cp = np;
            }
            ((FixSubBlock*)cp)->block_ = b;
            ((FixSubBlock*)cp)->next_ = 0;
        }
        b->start_ = p;
        b->n_allocated_ = 0;
        fs->head_ = b;
    }

    {
        FixSubBlock* p = fs->head_->start_;

        fs->head_->start_ = p->next_;
        ++fs->head_->n_allocated_;

        if (fs->head_->start_ == 0) {
            fs->head_ = fs->head_->next_;
            fs->tail_ = fs->tail_->next_;
        }

        return (char*)p + 4;
    }
}

static void deallocate_from_fixed_pools(__mem_pool_obj* pool_obj, void* ptr, unsigned long size) {
    unsigned long i = 0;
    FixSubBlock* p;
    FixBlock* b;
    FixStart* fs;

    while (size > fix_pool_sizes[i]) {
        ++i;
    }

    fs = &pool_obj->fix_start[i];
    p = FixSubBlock_from_pointer(ptr);
    b = p->block_;

    if (b->start_ == 0 && fs->head_ != b) {
        if (fs->tail_ == b) {
            fs->head_ = fs->head_->prev_;
            fs->tail_ = fs->tail_->prev_;
        } else {
            b->prev_->next_ = b->next_;
            b->next_->prev_ = b->prev_;
            b->next_ = fs->head_;
            b->prev_ = b->next_->prev_;
            b->prev_->next_ = b;
            b->next_->prev_ = b;
            fs->head_ = b;
        }
    }

    p->next_ = b->start_;
    b->start_ = p;

    if (--b->n_allocated_ == 0) {
        if (fs->head_ == b) {
            fs->head_ = b->next_;
        }

        if (fs->tail_ == b) {
            fs->tail_ = b->prev_;
        }

        b->prev_->next_ = b->next_;
        b->next_->prev_ = b->prev_;

        if (fs->head_ == b) {
            fs->head_ = 0;
        }

        if (fs->tail_ == b) {
            fs->tail_ = 0;
        }

        deallocate_from_var_pools(pool_obj, b);
    }
}

void* __pool_alloc(__mem_pool* pool, unsigned long size) {
    __mem_pool_obj* pool_obj;

    if (size == 0) {
        return 0;
    }

    if (size > 0xFFFFFFCFUL) {
        return 0;
    }

    pool_obj = (__mem_pool_obj*)pool;
    if (size <= 68) {
        return allocate_from_fixed_pools(pool_obj, size);
    }

    return allocate_from_var_pools(pool_obj, size);
}

void __pool_free(__mem_pool* pool, void* ptr) {
    __mem_pool_obj* pool_obj;
    unsigned long size;

    if (ptr == 0) {
        return;
    }

    pool_obj = (__mem_pool_obj*)pool;
    size = __msize_inline(ptr);

    if (size <= 68) {
        deallocate_from_fixed_pools(pool_obj, ptr, size);
    } else {
        deallocate_from_var_pools(pool_obj, ptr);
    }
}

void* malloc(size_t size) {
    void* ptr;

    __begin_critical_region(malloc_pool_access);
    ptr = __pool_alloc(get_malloc_pool(), size);
    __end_critical_region(malloc_pool_access);
    return ptr;
}

extern void fn_80286F20(void*);

asm void free(void* ptr) {
    nofralloc
    stwu r1, -0x10(r1)
    mflr r0
    stw r0, 0x14(r1)
    stw r31, 0xc(r1)
    stw r30, 0x8(r1)
    mr r30, r3
    lbz r0, init_803DF080(r13)
    cmplwi r0, 0x0
    bne _fr_1
    lis r3, protopool_803DB818@ha
    li r4, 0x0
    addi r3, r3, protopool_803DB818@l
    li r5, 0x34
    bl memset
    li r0, 0x1
    stb r0, init_803DF080(r13)
_fr_1:
    cmplwi r30, 0x0
    lis r3, protopool_803DB818@ha
    addi r31, r3, protopool_803DB818@l
    beq _fr_7
    lwz r3, -0x4(r30)
    clrlwi. r0, r3, 31
    bne _fr_2
    lwz r5, 0x8(r3)
    b _fr_3
_fr_2:
    lwz r0, -0x8(r30)
    clrrwi r3, r0, 3
    subi r5, r3, 0x8
_fr_3:
    cmplwi r5, 0x44
    bgt _fr_4
    mr r3, r31
    mr r4, r30
    bl Block_subBlock
    b _fr_7
_fr_4:
    lwz r0, -0x4(r30)
    subi r4, r30, 0x8
    clrrwi r30, r0, 1
    mr r3, r30
    bl Block_link
    lwz r3, 0x10(r30)
    li r5, 0x0
    rlwinm. r0, r3, 0, 30, 30
    bne _fr_5
    lwz r0, 0xc(r30)
    clrrwi r4, r3, 3
    clrrwi r3, r0, 3
    subi r0, r3, 0x18
    cmplw r4, r0
    bne _fr_5
    li r5, 0x1
_fr_5:
    cmpwi r5, 0x0
    beq _fr_7
    lwz r4, 0x4(r30)
    cmplw r4, r30
    bne _fr_a
    li r4, 0x0
_fr_a:
    lwz r0, 0x0(r31)
    cmplw r0, r30
    bne _fr_b
    stw r4, 0x0(r31)
_fr_b:
    cmplwi r4, 0x0
    beq _fr_6
    lwz r0, 0x0(r30)
    stw r0, 0x0(r4)
    lwz r3, 0x0(r4)
    stw r4, 0x4(r3)
_fr_6:
    li r0, 0x0
    mr r3, r30
    stw r0, 0x4(r30)
    stw r0, 0x0(r30)
    bl fn_80286F20
_fr_7:
    lwz r0, 0x14(r1)
    lwz r31, 0xc(r1)
    lwz r30, 0x8(r1)
    mtlr r0
    addi r1, r1, 0x10
    blr
}
