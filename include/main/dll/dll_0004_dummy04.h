#ifndef MAIN_DLL_DLL_0004_DUMMY04_H_
#define MAIN_DLL_DLL_0004_DUMMY04_H_

#include "global.h"

typedef struct Dummy04InterfaceVTable
{
    int (*func03)(void);
    void (*func04)(void* obj, int arg1, int arg2, int arg3, int arg4);
    int (*func05)(void* obj, u16 arg1, int arg2, int arg3, int arg4);
    void (*onSetupPlayer)(void);
    void (*func07)(void* obj);
    void (*func08)(void);
    void (*onSelectSave)(int arg0, int arg1, int arg2, int arg3, int arg4);
    int (*func0A)(int arg0);
    int (*func0B)(void);
    void (*func0C)(void);
    int (*func0D)(int arg0);
    void (*func0E)(void);
    int (*func0F)(void);
    void (*func10)(void);
    int (*func11)(int arg0, int arg1);
    void (*func12)(void);
    void (*func13)(void);
    void (*func14)(void);
    void (*func15)(void* obj);
    void (*func16)(void);
    void (*func17)(void);
    void (*func18)(void);
    void (*func19)(void);
    void (*func1A)(void);
    void (*func1B)(void);
    void (*func1C)(void);
    int (*func1D)(void);
    void (*func1E)(void);
    void (*func1F)(void);
    void (*func20)(void);
    int (*func21)(void);
    int (*func22)(void);
    void (*func23)(void);
    int (*func24)(void);
    void (*func25)(void);
    void (*func26)(void);
} Dummy04InterfaceVTable;

typedef struct Dummy04Interface
{
    Dummy04InterfaceVTable* vtable;
} Dummy04Interface;

STATIC_ASSERT(offsetof(Dummy04InterfaceVTable, func04) == 0x04);
STATIC_ASSERT(offsetof(Dummy04InterfaceVTable, func05) == 0x08);
STATIC_ASSERT(offsetof(Dummy04InterfaceVTable, onSelectSave) == 0x18);
STATIC_ASSERT(offsetof(Dummy04InterfaceVTable, func0A) == 0x1C);
STATIC_ASSERT(offsetof(Dummy04InterfaceVTable, func0D) == 0x28);
STATIC_ASSERT(offsetof(Dummy04InterfaceVTable, func11) == 0x38);
STATIC_ASSERT(offsetof(Dummy04InterfaceVTable, func15) == 0x48);
STATIC_ASSERT(sizeof(Dummy04InterfaceVTable) == 0x90);

extern Dummy04Interface* gTitleMenuControlInterface;
extern Dummy04Interface* gTitleMenuControlInterfaceCopy;

void Dummy04_func14_nop(void);
void Dummy04_func26_nop(void);
void Dummy04_func25_nop(void);
int Dummy04_func24_ret_0(void);
void Dummy04_func23_nop(void);
int Dummy04_func22_ret_127(void);
int Dummy04_func21_ret_0(void);
void Dummy04_func20_nop(void);
void Dummy04_func1F_nop(void);
void Dummy04_func1E_nop(void);
int Dummy04_func1D_ret_0(void);
void Dummy04_func1C_nop(void);
void Dummy04_func1B_nop(void);
void Dummy04_func1A_nop(void);
void Dummy04_func19_nop(void);
void Dummy04_func18_nop(void);
void Dummy04_func17_nop(void);
void Dummy04_func16_nop(void);
void Dummy04_onSetupPlayer(void);
void Dummy04_func15_nop(void* obj);
void Dummy04_func13_nop(void);
void Dummy04_func12_nop(void);
int Dummy04_func11_ret_0(int arg0, int arg1);
void Dummy04_func10_nop(void);
int Dummy04_func0F_ret_0(void);
void Dummy04_func0E_nop(void);
int Dummy04_func0D_ret_0(int arg0);
void Dummy04_func0C_nop(void);
int Dummy04_func0B_ret_0(void);
int Dummy04_func0A_ret_0(int arg0);
void Dummy04_onSelectSave(int arg0, int arg1, int arg2, int arg3, int arg4);
void Dummy04_func08_nop(void);
void Dummy04_func07_nop(void* obj);
int Dummy04_func05_ret_0(void* obj, u16 arg1, int arg2, int arg3, int arg4);
void Dummy04_func04_nop(void* obj, int arg1, int arg2, int arg3, int arg4);
int Dummy04_func03_ret_m1(void);
void Dummy04_release(void);
void Dummy04_initialise(void);

#endif
