#include "ghidra_import.h"
#include "main/dll/DIM/DIM2conveyor.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b14();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern uint FUN_80017760();
extern int ObjHits_GetPriorityHit();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 ObjMsg_AllocQueue();
extern undefined4 FUN_8003b818();
extern int FUN_800480a0();
extern int FUN_8005af70();
extern int FUN_8005b398();
extern uint FUN_80060058();
extern int FUN_800600c4();
extern int FUN_800600e4();
extern undefined4 FUN_801b2550();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286888();
extern uint countLeadingZeros();

extern undefined4* DAT_803dd6d4;
extern void* DAT_803de7d0;
extern f32 FLOAT_803e5550;

/*
 * --INFO--
 *
 * Function: FUN_801b3658
 * EN v1.0 Address: 0x801B3658
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801B367C
 * EN v1.1 Size: 636b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b3658(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801b365c
 * EN v1.0 Address: 0x801B365C
 * EN v1.0 Size: 272b
 * EN v1.1 Address: 0x801B38F8
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b365c(undefined4 param_1,undefined4 param_2,uint param_3)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined8 uVar6;
  
  uVar6 = FUN_8028683c();
  iVar1 = (int)((ulonglong)uVar6 >> 0x20);
  for (iVar5 = 0; iVar5 < (int)(uint)*(ushort *)(iVar1 + 0x9a); iVar5 = iVar5 + 1) {
    iVar3 = FUN_800600c4(iVar1,iVar5);
    uVar2 = FUN_80060058(iVar3);
    if (param_3 == uVar2) {
      if ((int)uVar6 == 0) {
        *(uint *)(iVar3 + 0x10) = *(uint *)(iVar3 + 0x10) | 2;
        *(uint *)(iVar3 + 0x10) = *(uint *)(iVar3 + 0x10) | 1;
      }
      else {
        *(uint *)(iVar3 + 0x10) = *(uint *)(iVar3 + 0x10) & 0xfffffffd;
        *(uint *)(iVar3 + 0x10) = *(uint *)(iVar3 + 0x10) & 0xfffffffe;
      }
    }
  }
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(iVar1 + 0xa2); iVar5 = iVar5 + 1) {
    iVar3 = FUN_800600e4(iVar1,iVar5);
    iVar4 = FUN_800480a0(iVar3,0);
    if (param_3 == *(byte *)(iVar4 + 5)) {
      if ((int)uVar6 == 0) {
        *(uint *)(iVar3 + 0x3c) = *(uint *)(iVar3 + 0x3c) | 2;
      }
      else {
        *(uint *)(iVar3 + 0x3c) = *(uint *)(iVar3 + 0x3c) & 0xfffffffd;
      }
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b376c
 * EN v1.0 Address: 0x801B376C
 * EN v1.0 Size: 700b
 * EN v1.1 Address: 0x801B3A0C
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_801b376c(uint param_1,undefined4 param_2,int param_3)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  int local_18 [4];
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if (*(char *)(iVar3 + 2) == '\0') {
    uVar1 = FUN_80017690((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x20));
    if (uVar1 != 0) {
      *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
           *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) | 1;
      iVar2 = ObjHits_GetPriorityHit(param_1,local_18,(int *)0x0,(uint *)0x0);
      if ((iVar2 != 0) && (*(short *)(local_18[0] + 0x46) == 0x18d)) {
        *(undefined *)(iVar3 + 2) = 2;
        FUN_80006824(param_1,0x2c1);
        iVar2 = FUN_8005b398((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10));
        iVar2 = FUN_8005af70(iVar2);
        if (iVar2 != 0) {
          FUN_801b365c(iVar2,1,(uint)*(byte *)(iVar3 + 1));
          FUN_801b365c(iVar2,0,*(byte *)(iVar3 + 1) + 1);
        }
      }
    }
  }
  else if (*(char *)(param_3 + 0x80) == '\x01') {
    FUN_80017698((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x1e),1);
    *(undefined *)(iVar3 + 2) = 1;
  }
  uVar1 = countLeadingZeros((uint)*(byte *)(iVar3 + 2));
  return uVar1 >> 5;
}

/*
 * --INFO--
 *
 * Function: FUN_801b3a28
 * EN v1.0 Address: 0x801B3A28
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x801B3B38
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b3a28(int param_1)
{
  char in_r8;
  
  if ((*(char *)(*(int *)(param_1 + 0xb8) + 2) == '\x02') && (in_r8 != '\0')) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: dimbridgecogmai_release
 * EN v1.0 Address: 0x801B3A60
 * EN v1.0 Size: 144b
 * EN v1.1 Address: 0x801B3B7C
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimbridgecogmai_release(int param_1)
{
  int iVar1;
  
  if ((*(char **)(param_1 + 0xb8))[2] == '\x01') {
    *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
         *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 0xfffe;
  }
  else if (*(int *)(param_1 + 0xf4) == 0) {
    iVar1 = (int)**(char **)(param_1 + 0xb8);
    if (iVar1 != -1) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(iVar1,param_1,0xffffffff);
    }
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b3af0
 * EN v1.0 Address: 0x801B3AF0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801B3C0C
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b3af0(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801b3af4
 * EN v1.0 Address: 0x801B3AF4
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x801B3D1C
 * EN v1.1 Size: 120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801b3af4(int param_1,undefined4 param_2,int param_3)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x4c);
  *(undefined *)(param_3 + 0x56) = 0;
  if (((*(byte *)(iVar1 + 0x1d) & 2) != 0) && (*(char *)(param_3 + 0x80) == '\x01')) {
    FUN_80017698((int)*(short *)(iVar1 + 0x18),1);
    *(undefined *)(param_3 + 0x80) = 0;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: dimdismountpoint_func08
 * EN v1.0 Address: 0x801B3B58
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x801B3D94
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimdismountpoint_func08(int param_1)
{
  ObjGroup_RemoveObject(param_1,0xf);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b3b7c
 * EN v1.0 Address: 0x801B3B7C
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801B3DB8
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b3b7c(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b3ba4
 * EN v1.0 Address: 0x801B3BA4
 * EN v1.0 Size: 376b
 * EN v1.1 Address: 0x801B3DEC
 * EN v1.1 Size: 400b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b3ba4(int param_1)
{
  short sVar1;
  uint uVar2;
  uint uVar3;
  undefined4 uVar4;
  undefined4 unaff_r29;
  int iVar5;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  uVar2 = FUN_80017690((int)*(short *)(iVar5 + 0x1a));
  if (uVar2 != 0) {
    if (*(char *)(iVar5 + 0x1e) != -1) {
      sVar1 = *(short *)(iVar5 + 0x1a);
      if (sVar1 == 0x1e3) {
        uVar2 = FUN_80017690(0x182);
        uVar3 = FUN_80017690(0x183);
        uVar2 = uVar2 & 0xff | (uVar3 & 0x7f) << 1;
        uVar3 = FUN_80017690(0x184);
        uVar3 = uVar2 | (uVar3 & 0x3f) << 2;
        if (uVar3 == 7) {
          *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x8000;
          unaff_r29 = 0xffffffff;
          uVar4 = 2;
        }
        else {
          FUN_80017698((int)*(short *)(iVar5 + 0x1a),0);
          unaff_r29 = 0x1d;
          if (((uVar3 & 4) != 0) && (unaff_r29 = 0x1f, (uVar2 & 2) != 0)) {
            unaff_r29 = 0x3f;
          }
          uVar4 = 1;
        }
      }
      else if ((sVar1 < 0x1e3) && (sVar1 == 0x17a)) {
        uVar2 = FUN_80017690(0x181);
        if (uVar2 == 0) {
          FUN_80017698((int)*(short *)(iVar5 + 0x1a),0);
          unaff_r29 = 0x1f;
          uVar4 = 1;
        }
        else {
          *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x8000;
          unaff_r29 = 0xffffffff;
          uVar4 = 0;
        }
      }
      else {
        uVar4 = 0;
      }
      (**(code **)(*DAT_803dd6d4 + 0x48))(uVar4,param_1,unaff_r29);
    }
    if ((*(byte *)(iVar5 + 0x1d) & 2) == 0) {
      FUN_80017698((int)*(short *)(iVar5 + 0x18),1);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b3d1c
 * EN v1.0 Address: 0x801B3D1C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801B3F7C
 * EN v1.1 Size: 152b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b3d1c(short *param_1,int param_2)
{
}


/* Trivial 4b 0-arg blr leaves. */
void dimlavasmash_release(void) {}
void dimlavasmash_initialise(void) {}
void dimbridgecogmai_hitDetect(void) {}
void dimbridgecogmai_initialise(void) {}
void dimdismountpoint_hitDetect(void) {}
void dimdismountpoint_release(void) {}
void dimdismountpoint_initialise(void) {}
