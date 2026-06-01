#include "ghidra_import.h"
#include "main/mapEvent.h"
#include "main/dll/flybaddie1D7.h"
#include "main/dll/projball1D8.h"

#define SFXsc_clubhit02 653

extern undefined4 Music_Trigger();
extern undefined4 FUN_80006824();
extern byte gameTimerIsRunning();
extern double FUN_80006b3c();
extern byte FUN_80006b44();
extern undefined4 FUN_80006b4c();
extern undefined4 FUN_80006b50();
extern undefined4 FUN_80006b54();
extern undefined4 FUN_80006c88();
extern uint GameBit_Get();
extern undefined4 GameBit_Set();
extern undefined4 FUN_80017a98();
extern undefined4 FUN_80080f14();
extern undefined4 SCGameBitLatch_Update();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();
extern u8 *Obj_GetPlayerObject(void);
extern void gameTextShow(int p);

extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd72c;
extern f32 lbl_803DC074;
extern f32 lbl_803E5F10;
extern f32 lbl_803E5F14;

/*
 * --INFO--
 *
 * Function: nw_levcontrol_update
 * EN v1.0 Address: 0x801CFF20
 * EN v1.0 Size: 1472b
 * EN v1.1 Address: 0x801D04F0
 * EN v1.1 Size: 1472b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void nw_levcontrol_update(int param_1)
{
  int iVar1;
  short *psVar2;
  u8 cVar7;
  int iVar3;
  uint uVar4;
  uint uVar5;
  byte bVar8;
  uint uVar6;
  uint uVar9;
  float *pfVar10;

  iVar1 = param_1;
  pfVar10 = *(float **)(iVar1 + 0xb8);
  psVar2 = (short *)Obj_GetPlayerObject();
  if (*pfVar10 > lbl_803E5F10) {
    gameTextShow(0x435);
    *pfVar10 = *pfVar10 - lbl_803DC074;
    if (*pfVar10 < lbl_803E5F10) {
      *pfVar10 = lbl_803E5F10;
    }
  }
  cVar7 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(iVar1 + 0xac));
  if (cVar7 != '\x01') {
    (**(code **)(*DAT_803dd72c + 0x44))((int)*(char *)(iVar1 + 0xac),1);
  }
  cVar7 = (**(code **)(*DAT_803dd72c + 0x40))(7);
  if (cVar7 == '\x01') {
    (**(code **)(*DAT_803dd72c + 0x44))(7,2);
    GameBit_Set(0xf22,1);
    GameBit_Set(0xf23,1);
    GameBit_Set(0xf24,1);
    GameBit_Set(0xf25,1);
  }
  iVar3 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
  if (iVar3 == 0) {
    if ((*(short *)(pfVar10 + 4) != 0x1a) &&
       (*(undefined2 *)(pfVar10 + 4) = 0x1a, (*((uint*)pfVar10 + 2) & 0x10) != 0)) {
      Music_Trigger((int *)0x1a,1);
    }
  }
  else if ((*(short *)(pfVar10 + 4) != -1) &&
          (*(undefined2 *)(pfVar10 + 4) = 0xffff, (*((uint*)pfVar10 + 2) & 0x10) != 0)) {
    Music_Trigger((int *)0x1a,0);
  }
  SCGameBitLatch_Update(pfVar10 + 2,8,-1,-1,0x3a0,(int *)0x35);
  SCGameBitLatch_Update(pfVar10 + 2,0x10,-1,-1,0x3a1,(int *)(int)*(short *)(pfVar10 + 4));
  SCGameBitLatch_Update(pfVar10 + 2,0x20,-1,-1,0x393,(int *)0x36);
  SCGameBitLatch_Update(pfVar10 + 2,0x40,-1,-1,0xcbb,(int *)0xc4);
  uVar9 = 0;
  uVar4 = GameBit_Get(0x19f);
  uVar5 = GameBit_Get(0x19d);
  if ((uVar5 != uVar4) && (bVar8 = gameTimerIsRunning(), bVar8 != 0)) {
    uVar9 = 1;
  }
  GameBit_Set(0xf31,uVar9);
  SCGameBitLatch_Update(pfVar10 + 2,0x80,-1,-1,0xf31,(int *)0xaf);
  uVar4 = GameBit_Get(0x398);
  if ((uVar4 != 0) &&
     (cVar7 = (**(code **)(*DAT_803dd72c + 0x4c))((int)*(char *)(iVar1 + 0xac),0x1f), cVar7 == '\0')
     ) {
    (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(iVar1 + 0xac),0x1f,1);
  }
  if (((*((uint*)pfVar10 + 2) & 2) == 0) || (bVar8 = FUN_80006b44(), bVar8 == 0)) {
    switch(*(undefined *)(pfVar10 + 1)) {
    case 0:
      uVar4 = GameBit_Get(0x19d);
      if (uVar4 != 0) {
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,iVar1,0xffffffff);
        *(undefined *)(pfVar10 + 1) = 2;
        GameBit_Set(0xecd,1);
      }
      break;
    case 1:
      (**(code **)(*DAT_803dd6d4 + 0x54))(iVar1,0x64a);
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,iVar1,0x20);
      *(undefined *)(pfVar10 + 1) = 2;
      GameBit_Set(0xecd,1);
      break;
    case 2:
      iVar1 = fn_801CFD68((u8 *)pfVar10);
      if (iVar1 != 0) {
        *(undefined *)((int)pfVar10 + 5) = 0x32;
        *((uint*)pfVar10 + 2) = *((uint*)pfVar10 + 2) | 1;
      }
      break;
    case 3:
    case 4:
    case 5:
    case 6:
    case 7:
      fn_801CFD68((u8 *)pfVar10);
      break;
    case 8:
      iVar1 = fn_801CFD68((u8 *)pfVar10);
      if (iVar1 == 1) {
        *((uint*)pfVar10 + 2) = *((uint*)pfVar10 + 2) | 4;
      }
      break;
    case 9:
      if ((psVar2[0x58] & 0x1000U) != 0) {
        *(undefined *)(pfVar10 + 1) = 10;
      }
      break;
    case 10:
      if ((psVar2[0x58] & 0x1000U) == 0) {
        uVar6 = *((uint*)pfVar10 + 2);
        if ((uVar6 & 1) != 0) {
          *((uint*)pfVar10 + 2) = uVar6 & ~1;
          *((uint*)pfVar10 + 2) = *((uint*)pfVar10 + 2) | 2;
          FUN_80006b54(0x15,(uint)*(byte *)((int)pfVar10 + 5));
          FUN_80006b50();
          (**(code **)(*DAT_803dd72c + 0x1c))(psVar2 + 6,(int)*psVar2,0,0);
        }
        else if ((uVar6 & 4) != 0) {
          *((uint*)pfVar10 + 2) = uVar6 & 0xfffffffd;
          *((uint*)pfVar10 + 2) = *((uint*)pfVar10 + 2) & 0xfffffffb;
          FUN_80006b4c();
          Music_Trigger((int *)0xaf,0);
          GameBit_Set(0x19f,1);
        }
        else {
          iVar3 = (int)(FUN_80006b3c() / (double)lbl_803E5F14);
          FUN_80006b4c();
          FUN_80006b54(0x15,(uint)*(byte *)((int)pfVar10 + 5) + iVar3);
          FUN_80006b50();
        }
        (**(code **)(*DAT_803dd6d4 + 0x48))(*(undefined *)(pfVar10 + 3),iVar1,0xffffffff);
        *(undefined *)(pfVar10 + 1) = *(undefined *)((int)pfVar10 + 0xd);
      }
      break;
    case 0xb:
      uVar4 = GameBit_Get(0xecd);
      if (uVar4 != 0) {
        GameBit_Set(0xecd,0);
      }
      break;
    case 0xc:
      (**(code **)(*DAT_803dd6d4 + 0x54))(iVar1,0x5a);
      (**(code **)(*DAT_803dd6d4 + 0x48))(1,iVar1,8);
      *(undefined *)(pfVar10 + 1) = 0xb;
    }
  }
  else {
    FUN_80006824(0,SFXsc_clubhit02);
    (**(code **)(*DAT_803dd72c + 0x28))();
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: sh_tricky_getExtraSize
 * EN v1.0 Address: 0x801D069C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int sh_tricky_getExtraSize(void)
{
  return 1;
}

extern int *getTrickyObject(void);

#pragma scheduling off
#pragma peephole off
void sh_tricky_update(int *obj) {
    u8 *state;
    int *tricky;

    state = *(u8 **)((char *)obj + 0xb8);
    tricky = getTrickyObject();
    if (tricky == NULL) {
        return;
    }

    switch (state[0]) {
    case 0:
        if (GameBit_Get(0x94) != 0) {
            GameBit_Set(0x4e4, 0);
            GameBit_Set(0x4e5, 0);
            GameBit_Set(0xc11, 1);
            state[0] = 1;
        }
        break;
    case 1:
        state[0] = 2;
        break;
    case 2:
        if (((int (*)(int *, int *))(*(int *)(*(int *)(tricky[0x1a]) + 0x38)))(tricky, obj) !=
            0) {
            state[0] = 3;
        }
        break;
    case 3:
        if (GameBit_Get(0xbf) != 0) {
            GameBit_Set(0x4e4, 1);
            GameBit_Set(0x4e5, 1);
            GameBit_Set(0xc11, 0);
        }
        break;
    case 4:
        break;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
int EdibleMushroom_SeqFn(int *obj) {
    *(u8*)(*(int*)((char*)obj + 0xb8) + 0x139) = 1;
    return 0;
}
#pragma scheduling reset

extern uint GameBit_Get(int id);

#pragma scheduling off
#pragma peephole off
void sh_tricky_init(int* obj)
{
    u8* state = *(u8**)((char*)obj + 0xb8);
    if (GameBit_Get(0xbf) != 0) {
        *state = 4;
    } else {
        *state = 0;
    }
    *(u16*)((char*)obj + 0xb0) = (u16)(*(u16*)((char*)obj + 0xb0) | 0x6000);
}
#pragma peephole reset
#pragma scheduling reset

extern char lbl_803269F8[];
extern f32 lbl_803E5280;
extern MapEventInterface **gMapEventInterface;
extern void fn_80088870(char* a, char* b, char* c, char* d);
extern int getSaveGameLoadStatus(void);
extern void envFxActFn_800887f8(int id);
extern void getEnvfxActImmediately(int a, int b, int c, int d);
extern void getEnvfxAct(int a, int b, int c, int d);

#pragma scheduling off
#pragma peephole off
void nw_levcontrol_init(int* obj)
{
    char* base = lbl_803269F8;
    u8* state = *(u8**)((char*)obj + 0xb8);

    Obj_GetPlayerObject();
    *(u16*)((char*)obj + 0xb0) = (u16)(*(u16*)((char*)obj + 0xb0) | 0x6000);

    if (GameBit_Get(0x19f) != 0) {
        state[4] = 0xc;
    } else if (GameBit_Get(0x19d) != 0) {
        state[4] = 1;
    } else {
        state[4] = 0;
    }

    *(f32*)state = lbl_803E5280;

    fn_80088870(base + 0x8c, base + 0x54, base + 0xc4, base + 0xfc);

    if (getSaveGameLoadStatus() != 0) {
        envFxActFn_800887f8(0x3f);
        getEnvfxActImmediately(0, 0, 0x23c, 0);
    } else {
        envFxActFn_800887f8(0x1f);
        getEnvfxAct(0, 0, 0x23c, 0);
    }

    (*gMapEventInterface)->setAnimEvent(7, 0, 0);
    (*gMapEventInterface)->setAnimEvent(7, 2, 0);
    (*gMapEventInterface)->setAnimEvent(7, 5, 0);
    (*gMapEventInterface)->setAnimEvent(7, 10, 0);
    (*gMapEventInterface)->setAnimEvent(7, 0x1c, 0);
    (*gMapEventInterface)->setAnimEvent(7, 9, 1);
}
#pragma peephole reset
#pragma scheduling reset
