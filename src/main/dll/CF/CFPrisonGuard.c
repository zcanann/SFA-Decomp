#include "ghidra_import.h"
#include "main/dll/CF/CFPrisonGuard.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b94();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern uint FUN_80017760();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 FUN_8002fc3c();
extern undefined4 FUN_800305c4();
extern int ObjGroup_FindNearestObject();
extern undefined4 ObjHits_PollPriorityHitEffectWithCooldown();
extern undefined4 FUN_80039520();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();

extern f64 DOUBLE_803e4868;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e4850;
extern f32 FLOAT_803e4854;
extern f32 FLOAT_803e4858;
extern f32 FLOAT_803e485c;
extern f32 FLOAT_803e4860;
extern f32 FLOAT_803e4864;

/*
 * --INFO--
 *
 * Function: FUN_801899b4
 * EN v1.0 Address: 0x801899B4
 * EN v1.0 Size: 784b
 * EN v1.1 Address: 0x80189B68
 * EN v1.1 Size: 584b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801899b4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  uint uVar1;
  undefined2 *puVar2;
  int iVar3;
  int iVar4;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar5;
  int iVar6;
  double dVar7;
  double in_f31;
  double dVar8;
  double in_ps31_1;
  undefined8 uVar9;
  float local_48 [16];
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar9 = FUN_80286840();
  iVar3 = (int)((ulonglong)uVar9 >> 0x20);
  iVar4 = (int)uVar9;
  iVar5 = *(int *)(iVar3 + 0x4c);
  if (((char)*(byte *)(iVar4 + 0x1d) < '\0') &&
     (((*(byte *)(iVar4 + 0x1d) >> 6 & 1) == 0 || (*(char *)(iVar4 + 0x1c) != '\0')))) {
    if (*(char *)(iVar4 + 0x1c) == '\0') {
      if (*(char *)(iVar5 + 0x1e) == '\x02') {
        uVar1 = FUN_80017760(0xffffff38,200);
        *(short *)(iVar3 + 2) = (short)uVar1;
        uVar1 = FUN_80017760(0xffffff38,200);
        *(short *)(iVar3 + 4) = (short)uVar1;
      }
      ObjHits_PollPriorityHitEffectWithCooldown(iVar3,8,0xb4,0xf0,0xff,0x6f,(float *)(iVar4 + 0x20));
    }
    else {
      *(undefined2 *)(iVar3 + 2) = 0;
      *(undefined2 *)(iVar3 + 4) = 0;
      dVar7 = (double)*(float *)(iVar3 + 0x98);
      if (((double)FLOAT_803e4854 <= dVar7) && ((*(byte *)(iVar4 + 0x1d) >> 4 & 1) == 0)) {
        if (0 < *(short *)(iVar5 + 0x24)) {
          dVar7 = (double)FUN_80017698((int)*(short *)(iVar5 + 0x24),1);
        }
        if (*(char *)(iVar5 + 0x1e) == '\x01') {
          local_48[0] = FLOAT_803e4858;
          iVar3 = ObjGroup_FindNearestObject(0x41,iVar3,local_48);
          if (iVar3 != 0) {
            iVar5 = *(int *)(iVar3 + 0xb8);
            uVar1 = (uint)*(short *)(*(int *)(iVar3 + 0x4c) + 0x22);
            if (0 < (int)uVar1) {
              FUN_80017698(uVar1,1);
            }
            *(byte *)(iVar5 + 0x1d) = *(byte *)(iVar5 + 0x1d) & 0x7f | 0x80;
          }
        }
        else if ((*(char *)(iVar5 + 0x1e) == '\0') && (uVar1 = FUN_80017ae8(), (uVar1 & 0xff) != 0))
        {
          dVar8 = (double)FLOAT_803e4850;
          for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(iVar5 + 0x1f); iVar6 = iVar6 + 1) {
            puVar2 = FUN_80017aa4(0x24,0x259);
            *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(iVar3 + 0xc);
            *(float *)(puVar2 + 6) = (float)(dVar8 + (double)*(float *)(iVar3 + 0x10));
            *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(iVar3 + 0x14);
            *(undefined *)(puVar2 + 2) = 1;
            dVar7 = (double)FUN_80017ae4(dVar7,param_2,param_3,param_4,param_5,param_6,param_7,
                                         param_8,puVar2,5,*(undefined *)(iVar3 + 0xac),0xffffffff,
                                         *(uint **)(iVar3 + 0x30),in_r8,in_r9,in_r10);
          }
        }
        *(undefined *)(iVar4 + 0x1c) = 0;
        *(byte *)(iVar4 + 0x1d) = *(byte *)(iVar4 + 0x1d) & 0xef | 0x10;
      }
      *(byte *)(iVar4 + 0x1d) = *(byte *)(iVar4 + 0x1d) & 0xbf | 0x40;
      *(float *)(iVar4 + 8) = FLOAT_803e485c;
    }
    FUN_8002fc3c((double)*(float *)(iVar4 + 8),(double)FLOAT_803dc074);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80189cc4
 * EN v1.0 Address: 0x80189CC4
 * EN v1.0 Size: 328b
 * EN v1.1 Address: 0x80189DB0
 * EN v1.1 Size: 348b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80189cc4(int param_1,int param_2)
{
  byte bVar1;
  uint uVar2;
  undefined4 *puVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  if ((int)*(short *)(iVar4 + 0x24) != 0xffffffff) {
    uVar2 = FUN_80017690((int)*(short *)(iVar4 + 0x24));
    *(byte *)(param_2 + 0x1d) =
         (byte)((uVar2 & 0xff) << 5) & 0x20 | *(byte *)(param_2 + 0x1d) & 0xdf;
    bVar1 = *(byte *)(param_2 + 0x1d) >> 5 & 1;
    if ((bVar1 == 0) || (*(char *)(iVar4 + 0x1c) != '\x05')) {
      if (bVar1 == 0) {
        *(byte *)(param_2 + 0x1d) = *(byte *)(param_2 + 0x1d) & 0xbf;
      }
    }
    else {
      *(byte *)(param_2 + 0x1d) = *(byte *)(param_2 + 0x1d) & 0xbf | 0x40;
    }
  }
  if (*(char *)(param_2 + 0x1d) < '\0') {
    if (((int)*(short *)(iVar4 + 0x22) != 0xffffffff) &&
       (uVar2 = FUN_80017690((int)*(short *)(iVar4 + 0x22)), uVar2 == 0)) {
      *(byte *)(param_2 + 0x1d) = *(byte *)(param_2 + 0x1d) & 0x7f;
    }
  }
  else if (((int)*(short *)(iVar4 + 0x22) != 0xffffffff) &&
          (uVar2 = FUN_80017690((int)*(short *)(iVar4 + 0x22)), uVar2 != 0)) {
    *(byte *)(param_2 + 0x1d) = *(byte *)(param_2 + 0x1d) & 0x7f | 0x80;
  }
  puVar3 = (undefined4 *)FUN_80039520(param_1,0);
  if (puVar3 != (undefined4 *)0x0) {
    if ((char)*(byte *)(param_2 + 0x1d) < '\0') {
      if ((*(byte *)(param_2 + 0x1d) >> 5 & 1) == 0) {
        *puVar3 = 0x100;
      }
      else {
        *puVar3 = 0x200;
      }
    }
    else {
      *puVar3 = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80189e0c
 * EN v1.0 Address: 0x80189E0C
 * EN v1.0 Size: 596b
 * EN v1.1 Address: 0x80189F0C
 * EN v1.1 Size: 560b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80189e0c(uint param_1,int param_2)
{
  double dVar1;
  int iVar2;
  uint uVar3;
  undefined8 local_18;
  
  dVar1 = DOUBLE_803e4868;
  if (((char)*(byte *)(param_2 + 0x1d) < '\0') && ((*(byte *)(param_2 + 0x1d) >> 6 & 1) == 0)) {
    if (*(char *)(param_2 + 0x1c) == '\0') {
      *(int *)(param_2 + 0xc) =
           (int)-(FLOAT_803e4860 * FLOAT_803dc074 -
                 (float)((double)CONCAT44(0x43300000,*(uint *)(param_2 + 0xc) ^ 0x80000000) -
                        DOUBLE_803e4868));
      *(int *)(param_2 + 0x14) =
           (int)((float)((double)CONCAT44(0x43300000,*(uint *)(param_2 + 0xc) ^ 0x80000000) - dVar1)
                 * FLOAT_803dc074 +
                (float)((double)CONCAT44(0x43300000,*(uint *)(param_2 + 0x14) ^ 0x80000000) - dVar1)
                );
      if (*(int *)(param_2 + 0x18) < *(int *)(param_2 + 0x14)) {
        *(int *)(param_2 + 0x18) = *(int *)(param_2 + 0x14);
      }
      if ((*(int *)(param_2 + 0x10) == 0x800) && (*(int *)(param_2 + 0x14) < 0x800)) {
        FUN_80006824(param_1,0x374);
      }
      if (*(int *)(param_2 + 0x14) < 0) {
        if (0 < *(int *)(param_2 + 0x10)) {
          FUN_80006824(param_1,0x6e);
          iVar2 = *(int *)(param_2 + 0x18) / 200 + (*(int *)(param_2 + 0x18) >> 0x1f);
          uVar3 = iVar2 - (iVar2 >> 0x1f);
          if (0 < (int)uVar3) {
            local_18 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
            FUN_80006b94((double)(float)(local_18 - DOUBLE_803e4868));
          }
        }
        *(undefined4 *)(param_2 + 0xc) = 0;
        *(undefined4 *)(param_2 + 0x14) = 0;
      }
    }
    else {
      *(undefined *)(param_2 + 0x1c) = 0;
      *(undefined4 *)(param_2 + 0x18) = 0;
    }
    if (((*(int *)(param_2 + 0x10) < 0x40) && (0x3f < *(int *)(param_2 + 0x14))) ||
       ((0x3f < *(int *)(param_2 + 0x10) && (*(int *)(param_2 + 0x14) < 0x40)))) {
      FUN_80006824(param_1,0x374);
    }
    ObjHits_PollPriorityHitEffectWithCooldown(param_1,8,0xb4,0xf0,0xff,0x6f,(float *)(param_2 + 0x20));
    *(undefined4 *)(param_2 + 0x10) = *(undefined4 *)(param_2 + 0x14);
    local_18 = (double)CONCAT44(0x43300000,*(uint *)(param_2 + 0x14) ^ 0x80000000);
    FUN_800305c4((double)((float)(local_18 - DOUBLE_803e4868) / FLOAT_803e4864),param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018a060
 * EN v1.0 Address: 0x8018A060
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x8018A13C
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018a060(int param_1,char param_2)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (param_2 == '\0') {
    FUN_80017698((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x24),0);
    *(byte *)(iVar1 + 0x1d) = *(byte *)(iVar1 + 0x1d) & 0xdf;
  }
  else {
    FUN_80017698((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x24),1);
    *(byte *)(iVar1 + 0x1d) = *(byte *)(iVar1 + 0x1d) & 0xdf | 0x20;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018a0d0
 * EN v1.0 Address: 0x8018A0D0
 * EN v1.0 Size: 16b
 * EN v1.1 Address: 0x8018A1B0
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
byte FUN_8018a0d0(int param_1)
{
  return *(byte *)(*(int *)(param_1 + 0xb8) + 0x1d) >> 5 & 1;
}

/* chained byte bit-extract. */
u32 fn_80189C58(int *obj) { return (*((u8*)((int**)obj)[0xb8/4] + 0x1d) >> 5) & 1; }
