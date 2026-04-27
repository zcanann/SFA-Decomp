#include <stddef.h>

#include <dolphin.h>
#include <dolphin/hw_regs.h>

#include "dolphin/dsp/__dsp.h"

typedef struct DSPTaskStrings {
    char bootingTask[0x20];
    char iramMmemAddr[0x30];
    char iramDspAddr[0x30];
    char iramLength[0x30];
    char dramMmemAddr[0x30];
    char startVector[0x60];
} DSPTaskStrings;

extern const DSPTaskStrings sDSPTaskStrings;
#define DSP_BOOTING_TASK_MSG sDSPTaskStrings.bootingTask
#define IRAM_MMEM_ADDR_MSG sDSPTaskStrings.iramMmemAddr
#define IRAM_DSP_ADDR_MSG sDSPTaskStrings.iramDspAddr
#define IRAM_LENGTH_MSG sDSPTaskStrings.iramLength
#define DRAM_MMEM_ADDR_MSG sDSPTaskStrings.dramMmemAddr
#define START_VECTOR_MSG sDSPTaskStrings.startVector

extern DSPTaskInfo* __DSP_curr_task;
extern DSPTaskInfo* __DSP_first_task;
extern DSPTaskInfo* __DSP_last_task;
extern DSPTaskInfo* __DSP_tmp_task;
extern DSPTaskInfo* __DSP_rude_task;
extern int __DSP_rude_task_pending;

void __DSPHandler(__OSInterrupt intr, OSContext* context) {
    u8 unused[4];
    OSContext exceptionContext;
    u16 tmp;
    u32 mail;

    tmp = __DSPRegs[5];
    tmp = (tmp & ~0x28) | 0x80;
    __DSPRegs[5] = tmp;

    OSClearContext(&exceptionContext);
    OSSetCurrentContext(&exceptionContext);
    ASSERTMSGLINE(143, __DSP_curr_task != NULL, "__DSPHandler(): No current task! Someone set us up the bomb!\n");
    
    while (DSPCheckMailFromDSP() == 0)
        ;

    mail = DSPReadMailFromDSP();
    if ((__DSP_first_task->flags & (1 << (31 - 0x1E))) && (mail + 0x232F0000) == 2)
        mail = 0xDCD10003;

    switch (mail) {
    case 0xDCD10000:
        __DSP_first_task->state = 1;
        if (__DSP_first_task->init_cb != NULL)
            __DSP_first_task->init_cb(__DSP_first_task);
        break;
    case 0xDCD10001:
        __DSP_first_task->state = 1;
        if (__DSP_first_task->res_cb != NULL)
            __DSP_first_task->res_cb(__DSP_first_task);
        break;
    case 0xDCD10002:
        if (__DSP_rude_task_pending) {
            if (__DSP_first_task == __DSP_rude_task) {
                DSPSendMailToDSP(0xCDD10003);
                while (DSPCheckMailToDSP() != 0)
                    ;
                __DSP_rude_task = NULL;
                __DSP_rude_task_pending = 0;

                if (__DSP_first_task->res_cb != NULL)
                    __DSP_first_task->res_cb(__DSP_first_task);
            } else {
                DSPSendMailToDSP(0xCDD10001);
                while (DSPCheckMailToDSP() != 0)
                    ;
                __DSP_exec_task(__DSP_first_task, __DSP_rude_task);
                __DSP_first_task->state = 2;
                __DSP_first_task = __DSP_rude_task;
                __DSP_rude_task = NULL;
                __DSP_rude_task_pending = 0;
            }
        } else {
            if (__DSP_first_task->next == NULL) {
                if (__DSP_first_task == __DSP_curr_task) {
                    DSPSendMailToDSP(0xCDD10003);
                    while (DSPCheckMailToDSP() != 0)
                        ;
                    if (__DSP_first_task->res_cb != NULL)
                        __DSP_first_task->res_cb(__DSP_first_task);
                } else {
                    DSPSendMailToDSP(0xCDD10001);
                    while (DSPCheckMailToDSP() != 0)
                        ;
                    __DSP_exec_task(__DSP_first_task, __DSP_curr_task);
                    __DSP_first_task->state = 2;
                __DSP_first_task = __DSP_curr_task;
                }
            } else {
                DSPSendMailToDSP(0xCDD10001);
                while (DSPCheckMailToDSP() != 0)
                    ;
                __DSP_exec_task(__DSP_first_task, __DSP_first_task->next);
                __DSP_first_task->state = 2;
                __DSP_first_task = __DSP_first_task->next;
            }
        }
        break;
    case 0xDCD10003:
        if (__DSP_rude_task_pending) {
            if (__DSP_first_task->done_cb != NULL)
                __DSP_first_task->done_cb(__DSP_first_task);

            DSPSendMailToDSP(0xCDD10001);
            while (DSPCheckMailToDSP() != 0)
                ;
            __DSP_exec_task(NULL, __DSP_rude_task);
            __DSP_remove_task(__DSP_first_task);
            __DSP_first_task = __DSP_rude_task;
            __DSP_rude_task = NULL;
            __DSP_rude_task_pending = 0;
        } else {
            if (__DSP_first_task->next == NULL) {
                if (__DSP_first_task == __DSP_curr_task) {
                    if (__DSP_first_task->done_cb != NULL)
                        __DSP_first_task->done_cb(__DSP_first_task);

                    DSPSendMailToDSP(0xCDD10002);
                    while (DSPCheckMailToDSP() != 0)
                        ;
                    __DSP_first_task->state = 3;
                    __DSP_remove_task(__DSP_first_task);
                } else {
                    if (__DSP_first_task->done_cb != NULL)
                        __DSP_first_task->done_cb(__DSP_first_task);

                    DSPSendMailToDSP(0xCDD10001);
                    while (DSPCheckMailToDSP() != 0)
                        ;
                    __DSP_first_task->state = 3;
                    __DSP_exec_task(NULL, __DSP_curr_task);
                    __DSP_first_task = __DSP_curr_task;
                    __DSP_remove_task(__DSP_last_task);
                }
            } else {
                if (__DSP_first_task->done_cb != NULL)
                    __DSP_first_task->done_cb(__DSP_first_task);

                DSPSendMailToDSP(0xCDD10001);
                while (DSPCheckMailToDSP() != 0)
                    ;
                __DSP_first_task->state = 3;
                __DSP_exec_task(NULL, __DSP_first_task->next);
                __DSP_first_task = __DSP_first_task->next;
                __DSP_remove_task(__DSP_first_task->prev);
            }
        }
        break;
    case 0xDCD10004:
        if (__DSP_first_task->req_cb != NULL)
            __DSP_first_task->req_cb(__DSP_first_task);
        break;
    default:
        ASSERTMSGLINEV(519, 0, "__DSPHandler(): Unknown msg from DSP 0x%08X - task sync failed!\n", mail);
    }

    OSClearContext(&exceptionContext);
    OSSetCurrentContext(context);
}

void __DSP_exec_task(DSPTaskInfo* curr, DSPTaskInfo* next) {
    ASSERTMSGLINE(552, next != NULL, "__DSP_exec_task(): NULL task. It is to weep.\n");

    if (curr != NULL) {
        DSPSendMailToDSP((u32)curr->dram_mmem_addr);
        while (DSPCheckMailToDSP() != 0)
            ;
        DSPSendMailToDSP(curr->dram_length);
        while (DSPCheckMailToDSP() != 0)
            ;
        DSPSendMailToDSP(curr->dram_addr);
        while (DSPCheckMailToDSP() != 0)
            ;
    } else {
        DSPSendMailToDSP(0);
        while (DSPCheckMailToDSP() != 0)
            ;
        DSPSendMailToDSP(0);
        while (DSPCheckMailToDSP() != 0)
            ;
        DSPSendMailToDSP(0);
        while (DSPCheckMailToDSP() != 0)
            ;
    }

    DSPSendMailToDSP((u32)next->iram_mmem_addr);
    while (DSPCheckMailToDSP() != 0)
        ;

    DSPSendMailToDSP(next->iram_length);
    while (DSPCheckMailToDSP() != 0)
        ;

    DSPSendMailToDSP(next->iram_addr);
    while (DSPCheckMailToDSP() != 0)
        ;

    if (next->state == 0) {
        DSPSendMailToDSP(next->dsp_init_vector);
        while (DSPCheckMailToDSP() != 0)
            ;
        DSPSendMailToDSP(0);
        while (DSPCheckMailToDSP() != 0)
            ;
        DSPSendMailToDSP(0);
        while (DSPCheckMailToDSP() != 0)
            ;
        DSPSendMailToDSP(0);
        while (DSPCheckMailToDSP() != 0)
            ;
    } else {
        DSPSendMailToDSP(next->dsp_resume_vector);
        while (DSPCheckMailToDSP() != 0)
            ;

        DSPSendMailToDSP((u32)next->dram_mmem_addr);
        while (DSPCheckMailToDSP() != 0)
            ;

        DSPSendMailToDSP(next->dram_length);
        while (DSPCheckMailToDSP() != 0)
            ;

        DSPSendMailToDSP(next->dram_addr);
        while (DSPCheckMailToDSP() != 0)
            ;
    }
}

void __DSP_boot_task(DSPTaskInfo* task) {
    volatile u32 mail;

    ASSERTMSGLINE(634, task != NULL, "__DSP_boot_task(): NULL task!\n");
    while (DSPCheckMailFromDSP() == 0)
        ;

    mail = DSPReadMailFromDSP();
    ASSERTMSGLINEV(640, mail == 0x8071FEED, "__DSP_boot_task(): Failed to sync DSP on boot! (0x%08X)\n", mail);

    DSPSendMailToDSP(0x80F3A001);
    while (DSPCheckMailToDSP() != 0)
        ;

    DSPSendMailToDSP((u32)task->iram_mmem_addr);
    while (DSPCheckMailToDSP() != 0)
        ;

    DSPSendMailToDSP(0x80F3C002);
    while (DSPCheckMailToDSP() != 0)
        ;

    DSPSendMailToDSP(task->iram_addr & 0xFFFF);
    while (DSPCheckMailToDSP() != 0)
        ;

    DSPSendMailToDSP(0x80F3A002);
    while (DSPCheckMailToDSP() != 0)
        ;

    DSPSendMailToDSP(task->iram_length);
    while (DSPCheckMailToDSP() != 0)
        ;

    DSPSendMailToDSP(0x80F3B002);
    while (DSPCheckMailToDSP() != 0)
        ;

    DSPSendMailToDSP(0);
    while (DSPCheckMailToDSP() != 0)
        ;

    DSPSendMailToDSP(0x80F3D001);
    while (DSPCheckMailToDSP() != 0)
        ;

    DSPSendMailToDSP(task->dsp_init_vector);
    while (DSPCheckMailToDSP() != 0)
        ;

    __DSP_debug_printf(DSP_BOOTING_TASK_MSG, (u32)task);
    __DSP_debug_printf(IRAM_MMEM_ADDR_MSG, (u32)task->iram_mmem_addr);
    __DSP_debug_printf(IRAM_DSP_ADDR_MSG, task->iram_addr);
    __DSP_debug_printf(IRAM_LENGTH_MSG, task->iram_length);
    __DSP_debug_printf(DRAM_MMEM_ADDR_MSG, task->dram_length);
    __DSP_debug_printf(START_VECTOR_MSG, task->dsp_init_vector);
}

void __DSP_add_task(DSPTaskInfo* task) {
    DSPTaskInfo* temp;

    if (__DSP_first_task == NULL) {
        __DSP_curr_task = task;
        __DSP_first_task = __DSP_last_task = task;
        task->next = task->prev = NULL;
        return;
    }

    temp = __DSP_first_task;
    while (temp != NULL) {
        if (task->priority < temp->priority) {
            task->prev = temp->prev;
            temp->prev = task;
            task->next = temp;
            if (task->prev == NULL)
                __DSP_first_task = task;
            else
                task->prev->next = task;
            break;
        }
        temp = temp->next;
    }

    if (temp == NULL) {
        __DSP_last_task->next = task;
        task->next = NULL;
        task->prev = __DSP_last_task;
        __DSP_last_task = task;
    }
}

void __DSP_remove_task(DSPTaskInfo* task) {
    ASSERTMSGLINE(813, task != NULL, "__DSP_remove_task(): NULL task! Why? WHY?!?!\n");
    task->flags = 0;
    task->state = 3;

    if (__DSP_first_task == task) {
        if (task->next != NULL) {
            __DSP_first_task = task->next;
            task->next->prev = NULL;
        }
        else
            __DSP_first_task = __DSP_last_task = __DSP_curr_task = NULL;
        return;
    }

    if (__DSP_last_task == task) {
        __DSP_last_task = task->prev;
        task->prev->next = NULL;
        __DSP_curr_task = __DSP_first_task;
        return;
    }

    __DSP_curr_task = task->next;
    task->prev->next = task->next;
    task->next->prev = task->prev;
}
