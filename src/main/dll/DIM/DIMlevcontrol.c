#include "ghidra_import.h"
#include "main/dll/DIM/DIMlevcontrol.h"

#define SFXfoot_dinostep 0x1fe
#define SFXfoot_water_roll 0x201
#define SFXthorntail_annoyed1 0x202
#define SFXbaddie_eggsnatch_sniff1 705

extern bool FUN_800067f0();
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006ba8();
extern char FUN_80006bd0();
extern uint FUN_80006bf8();
extern uint FUN_80006c00();
extern uint FUN_80006c10();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern double FUN_80017708();
extern int FUN_80017a98();
extern undefined4 FUN_8002fc3c();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjPath_GetPointWorldPosition();
extern int FUN_8003964c();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8011e800();
extern undefined4 FUN_8011e844();
extern undefined4 FUN_8011e868();
extern undefined4 FUN_801b2260();
extern undefined4 FUN_801b2640();
extern undefined8 FUN_801b2644();
extern undefined4 FUN_80286838();
extern undefined4 FUN_80286884();
extern int FUN_80294d38();
extern undefined4 FUN_80294d40();
extern int FUN_80294dbc();

extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dcb68;
extern undefined4 DAT_803dcb6a;
extern undefined4 DAT_803dcb6c;
extern undefined4 DAT_803dcb74;
extern undefined4 DAT_803dcb78;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6e8;
extern void* DAT_803de7d0;
extern f64 DOUBLE_803e5558;
extern f64 DOUBLE_803e5578;
extern f32 lbl_803DC074;
extern f32 lbl_803DCB5C;
extern f32 lbl_803DCB60;
extern f32 lbl_803DCB64;
extern f32 lbl_803DCB70;
extern f32 lbl_803E5584;
extern f32 lbl_803E5588;

/*
 * --INFO--
 *
 * Function: FUN_801b2550
 * EN v1.0 Address: 0x801B2550
 * EN v1.0 Size: 1672b
 * EN v1.1 Address: 0x801B2B04
 * EN v1.1 Size: 1560b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b2550(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11)
{
  short sVar1;
  short sVar3;
  int iVar2;
  short *psVar4;
  int iVar5;
  uint uVar6;
  char cVar7;
  bool bVar8;
  bool bVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  double dVar14;
  double dVar15;
  short *local_38 [2];
  undefined4 local_30;
  uint uStack_2c;
  undefined8 local_28;
  
  psVar4 = (short *)FUN_80286838();
  iVar13 = *(int *)(psVar4 + 0x26);
  bVar9 = false;
  *(undefined *)(param_11 + 0x56) = 0;
  *(ushort *)(param_11 + 0x6e) = *(ushort *)(param_11 + 0x6e) & 0xf9f7;
  iVar12 = *(int *)(psVar4 + 0x5c);
  if (*(char *)(iVar12 + 0xac) == '\x03') {
    iVar13 = FUN_80017a98();
    FUN_8011e868(0x16);
    FUN_8011e844(0x17);
    FUN_8011e800(1);
    iVar5 = (**(code **)(*DAT_803dd6d0 + 0x10))();
    if ((iVar5 != 0x51) && (iVar5 != 0x4c)) {
      local_38[0] = psVar4;
      (**(code **)(*DAT_803dd6d0 + 0x1c))(0x51,1,0,4,local_38,0x32,0xff);
    }
    if (iVar5 == 0x51) {
      iVar5 = FUN_8003964c((int)psVar4,0);
      if (*(char *)(iVar12 + 0xb0) < '\x01') {
        uVar6 = GameBit_Get(0xdb);
        if (uVar6 == 0) {
          (**(code **)(*DAT_803dd6e8 + 0x38))(0x4b9,0x14,0x8c,1);
          GameBit_Set(0xdb,1);
        }
        cVar7 = FUN_80006bd0(0);
        uStack_2c = (int)cVar7 ^ 0x80000000;
        local_30 = 0x43300000;
        iVar11 = (int)(-lbl_803DCB70 *
                      (f32)(s32)uStack_2c);
        local_28 = (double)(longlong)iVar11;
        if (iVar11 == 0) {
          if (*(int *)(iVar12 + 0xa8) != 0) {
            FUN_80006824((uint)psVar4,SFXfoot_dinostep);
          }
        }
        else {
          sVar1 = *(short *)(iVar5 + 2);
          sVar3 = sVar1;
          if (sVar1 < 0) {
            sVar3 = -sVar1;
          }
          if ((int)DAT_803dcb6a - (int)DAT_803dcb6c < (int)sVar3) {
            if (iVar11 < 0) {
              iVar10 = -1;
            }
            else if (iVar11 < 1) {
              iVar10 = 0;
            }
            else {
              iVar10 = 1;
            }
            if (sVar1 < 0) {
              iVar2 = -1;
            }
            else if (sVar1 < 1) {
              iVar2 = 0;
            }
            else {
              iVar2 = 1;
            }
            if (iVar2 == iVar10) {
              iVar11 = (iVar11 * ((int)DAT_803dcb6a - (int)sVar3)) / (int)DAT_803dcb6c;
            }
          }
          *(short *)(iVar5 + 2) = *(short *)(iVar5 + 2) + (short)iVar11;
          FUN_800068c4((uint)psVar4,0x1ff);
        }
        *(int *)(iVar12 + 0xa8) = iVar11;
        if (0 < *(short *)(iVar12 + 0xa4)) {
          *(ushort *)(iVar12 + 0xa4) = *(short *)(iVar12 + 0xa4) - (ushort)DAT_803dc070;
        }
        if (0 < *(short *)(iVar12 + 0xa6)) {
          *(ushort *)(iVar12 + 0xa6) = *(short *)(iVar12 + 0xa6) - (ushort)DAT_803dc070;
        }
        uVar6 = FUN_80006c10(0);
        if (((uVar6 & 0x100) == 0) || (0 < *(short *)(iVar12 + 0xa4))) {
          FUN_8000680c((int)psVar4,2);
        }
        else {
          FUN_80006ba8(0,0x100);
          iVar5 = FUN_80294d38(iVar13);
          if (iVar5 < 1) {
            FUN_80006824((uint)psVar4,0x40c);
          }
          else {
            *(byte *)(iVar12 + 0xae) = *(char *)(iVar12 + 0xae) + DAT_803dc070;
            bVar8 = FUN_800067f0((int)psVar4,2);
            if (!bVar8) {
              FUN_80006824((uint)psVar4,SFXfoot_water_roll);
              FUN_80006824((uint)psVar4,SFXthorntail_annoyed1);
            }
          }
        }
        if (DAT_803dcb68 < *(byte *)(iVar12 + 0xae)) {
          *(byte *)(iVar12 + 0xae) = DAT_803dcb68;
        }
        (**(code **)(*DAT_803dd6e8 + 0x5c))(*(undefined *)(iVar12 + 0xae));
        local_28 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar12 + 0xae));
        dVar15 = (double)(float)(local_28 - DOUBLE_803e5578);
        dVar14 = (double)lbl_803DCB64;
        *(float *)(iVar12 + 0x98) = (float)(dVar15 * dVar14 + (double)lbl_803DCB60);
        uVar6 = FUN_80006bf8(0);
        if (((((uVar6 & 0x100) != 0) || (*(byte *)(iVar12 + 0xae) == DAT_803dcb68)) &&
            (*(short *)(iVar12 + 0xa4) < 1)) && (iVar5 = FUN_80294d38(iVar13), 0 < iVar5)) {
          FUN_80006ba8(0,0x100);
          dVar14 = (double)FUN_80294d40(iVar13,-1);
          *(undefined *)(iVar12 + 0xad) = 1;
          *(undefined *)(iVar12 + 0xae) = 0;
        }
        FUN_801b2640(dVar14,dVar15,param_3,param_4,param_5,param_6,param_7,param_8);
        if (((*(char *)(psVar4 + 0x56) == '\x13') && (*(char *)(iVar12 + 0xb2) == '\0')) &&
           ((uVar6 = GameBit_Get(0xc17), uVar6 != 0 && (uVar6 = GameBit_Get(0xa21), uVar6 != 0))))
        {
          *(undefined *)(iVar12 + 0xb2) = 1;
          *(undefined *)(iVar12 + 0xb1) = 1;
        }
        if ((*(char *)(iVar12 + 0xb1) != '\0') &&
           (*(byte *)(iVar12 + 0xb1) = *(char *)(iVar12 + 0xb1) + DAT_803dc070,
           0x3c < *(byte *)(iVar12 + 0xb1))) {
          bVar9 = true;
        }
        if ((bVar9) || (uVar6 = FUN_80006c00(0), (uVar6 & 0x200) != 0)) {
          FUN_80006ba8(0,0x200);
          FUN_8011e800(0);
          (**(code **)(*DAT_803dd6e8 + 0x60))();
          (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,1,0,0,0,0xff);
          *(undefined *)(iVar12 + 0xac) = 5;
          *(undefined *)(iVar12 + 0xb0) = 0x3c;
          *(byte *)(param_11 + 0x90) = *(byte *)(param_11 + 0x90) | 4;
          *(byte *)((int)psVar4 + 0xaf) = *(byte *)((int)psVar4 + 0xaf) & 0xf7;
          bVar9 = FUN_800067f0((int)psVar4,8);
          if (bVar9) {
            FUN_800067f0((int)psVar4,0);
          }
          FUN_8000680c((int)psVar4,2);
        }
        FUN_8002fc3c((double)lbl_803DCB5C,(double)lbl_803DC074);
      }
      else {
        *(byte *)(iVar12 + 0xb0) = *(char *)(iVar12 + 0xb0) - DAT_803dc070;
        if (*(char *)(iVar12 + 0xb0) < '\x01') {
          (**(code **)(*DAT_803dd6e8 + 0x58))(DAT_803dcb68,0x5d5);
        }
      }
    }
  }
  else {
    psVar4[3] = psVar4[3] & 0xbfff;
    iVar5 = FUN_8003964c((int)psVar4,0);
    *(short *)(iVar5 + 2) = *psVar4 - (short)((int)*(char *)(iVar13 + 0x28) << 8);
    *psVar4 = (short)((int)*(char *)(iVar13 + 0x28) << 8);
    *(undefined *)(iVar12 + 0xac) = 4;
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b2bd8
 * EN v1.0 Address: 0x801B2BD8
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x801B311C
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b2bd8(int param_1)
{
  if (*(short *)(param_1 + 0x46) != 0x1d6) {
    (**(code **)(*DAT_803dd6e8 + 0x60))();
    FUN_80006b0c(DAT_803de7d0);
    DAT_803de7d0 = (void*)0x0;
  }
  ObjGroup_RemoveObject(param_1,3);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b2c40
 * EN v1.0 Address: 0x801B2C40
 * EN v1.0 Size: 140b
 * EN v1.1 Address: 0x801B3180
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b2c40(undefined2 *param_1)
{
  undefined2 uVar1;
  int iVar2;
  
  if (param_1[0x23] == 0x1d6) {
    FUN_8003b818((int)param_1);
  }
  else {
    iVar2 = *(int *)(param_1 + 0x5c);
    uVar1 = *param_1;
    *param_1 = (short)((int)*(char *)(*(int *)(param_1 + 0x26) + 0x28) << 8);
    FUN_8003b818((int)param_1);
    *param_1 = uVar1;
    ObjPath_GetPointWorldPosition(param_1,0,(float *)(iVar2 + 0x8c),(undefined4 *)(iVar2 + 0x90),
                 (float *)(iVar2 + 0x94),0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b2ccc
 * EN v1.0 Address: 0x801B2CCC
 * EN v1.0 Size: 1324b
 * EN v1.1 Address: 0x801B321C
 * EN v1.1 Size: 1120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b2ccc(double param_1,double param_2,double param_3,double param_4,undefined8 param_5,
                 undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  byte bVar4;
  int iVar5;
  int *piVar6;
  double dVar7;
  undefined8 uVar8;
  double dVar9;
  double dVar10;
  short *local_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  
  iVar5 = *(int *)(param_9 + 0x26);
  if (param_9[0x23] == 0x1d6) {
    FUN_801b2260(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  else {
    if (((*(byte *)((int)param_9 + 0xaf) & 8) != 0) &&
       (uVar1 = GameBit_Get((int)*(short *)(iVar5 + 0x1a)), uVar1 != 0)) {
      *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
    }
    piVar6 = *(int **)(param_9 + 0x5c);
    iVar2 = FUN_80017a98();
    iVar3 = FUN_80294dbc(iVar2);
    if (iVar3 == 0) {
      *piVar6 = iVar2;
    }
    else {
      *piVar6 = 0;
    }
    param_9[3] = param_9[3] & 0xbfff;
    bVar4 = *(byte *)(piVar6 + 0x2b);
    if (bVar4 == 4) {
      FUN_801b2644();
      uVar1 = GameBit_Get((int)*(short *)(iVar5 + 0x1a));
      if (uVar1 == 0) {
        if ((*piVar6 != 0) && (uVar1 = GameBit_Get((int)*(short *)(iVar5 + 0x1e)), uVar1 == 0)) {
          dVar7 = FUN_80017708((float *)(param_9 + 0xc),(float *)(*piVar6 + 0x18));
          uStack_1c = *(short *)(iVar5 + 0x26) * DAT_803dcb78 ^ 0x80000000;
          local_20 = 0x43300000;
          if (dVar7 < (double)((f32)(s32)uStack_1c /
                              lbl_803E5584)) {
            *(undefined *)(piVar6 + 0x2b) = 1;
          }
        }
      }
      else {
        *(undefined *)(piVar6 + 0x2b) = 5;
      }
      *(undefined *)((int)piVar6 + 0xad) = 0;
      *(undefined2 *)(piVar6 + 0x29) = 0;
      *(undefined2 *)((int)piVar6 + 0xa6) = 0;
    }
    else if (bVar4 < 4) {
      if (bVar4 == 1) {
        uVar1 = GameBit_Get((int)*(short *)(iVar5 + 0x1a));
        if (uVar1 == 0) {
          uVar1 = GameBit_Get((int)*(short *)(iVar5 + 0x1e));
          if (uVar1 == 0) {
            if (*piVar6 == 0) {
              *(undefined *)(piVar6 + 0x2b) = 4;
            }
            else {
              *(byte *)((int)piVar6 + 0xaf) = *(char *)((int)piVar6 + 0xaf) + DAT_803dc070;
              if (10 < *(byte *)((int)piVar6 + 0xaf)) {
                *(undefined *)((int)piVar6 + 0xaf) = 0;
                for (bVar4 = 0; bVar4 < 9; bVar4 = bVar4 + 1) {
                  uVar1 = (uint)bVar4;
                  piVar6[uVar1 + 5] = piVar6[uVar1 + 6];
                  piVar6[uVar1 + 0xf] = piVar6[uVar1 + 0x10];
                  piVar6[uVar1 + 0x19] = piVar6[uVar1 + 0x1a];
                  if ((uVar1 == 0) || ((float)piVar6[2] < (float)piVar6[uVar1 + 0xf])) {
                    piVar6[2] = piVar6[uVar1 + 0xf];
                  }
                }
                piVar6[0xe] = *(int *)(*piVar6 + 0xc);
                piVar6[0x18] = *(int *)(*piVar6 + 0x10);
                piVar6[0x22] = *(int *)(*piVar6 + 0x14);
                piVar6[1] = piVar6[5];
                piVar6[3] = piVar6[0x19];
              }
              if (0 < *(short *)(piVar6 + 0x29)) {
                *(ushort *)(piVar6 + 0x29) = *(short *)(piVar6 + 0x29) - (ushort)DAT_803dc070;
              }
              if (0 < *(short *)((int)piVar6 + 0xa6)) {
                *(ushort *)((int)piVar6 + 0xa6) =
                     *(short *)((int)piVar6 + 0xa6) - (ushort)DAT_803dc070;
              }
              dVar7 = FUN_80017708((float *)(param_9 + 0xc),(float *)(*piVar6 + 0x18));
              piVar6[4] = (int)(float)dVar7;
              dVar7 = (double)(float)piVar6[2];
              dVar9 = (double)(float)piVar6[3];
              dVar10 = (double)(float)piVar6[4];
              uVar8 = FUN_801b2644();
              FUN_801b2640(uVar8,dVar7,dVar9,dVar10,param_5,param_6,param_7,param_8);
              uStack_1c = *(short *)(iVar5 + 0x26) * DAT_803dcb74 ^ 0x80000000;
              local_20 = 0x43300000;
              if ((f32)(s32)uStack_1c / lbl_803E5584
                  < (float)piVar6[4]) {
                *(undefined *)(piVar6 + 0x2b) = 4;
              }
            }
          }
          else {
            *(undefined *)(piVar6 + 0x2b) = 4;
          }
        }
        else {
          *(undefined *)(piVar6 + 0x2b) = 5;
        }
      }
      else if ((bVar4 == 0) && (uVar1 = GameBit_Get((int)*(short *)(iVar5 + 0x1c)), uVar1 != 0)) {
        *(undefined *)(piVar6 + 0x2b) = 4;
      }
    }
    else if (bVar4 < 6) {
      if (*(char *)(piVar6 + 0x2c) < '\x01') {
        if ((*(byte *)((int)param_9 + 0xaf) & 1) != 0) {
          *(undefined *)((int)piVar6 + 0xae) = 0;
          *(undefined *)((int)piVar6 + 0xb1) = 0;
          local_28[0] = param_9;
          (**(code **)(*DAT_803dd6d0 + 0x1c))(0x51,1,0,4,local_28,0x32,0xff);
          FUN_80006ba8(0,0x100);
          *(undefined *)(piVar6 + 0x2b) = 3;
          (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
          *(undefined *)(piVar6 + 0x2c) = 0x3c;
          *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 8;
        }
      }
      else {
        *(byte *)(piVar6 + 0x2c) = *(char *)(piVar6 + 0x2c) - DAT_803dc070;
      }
      *(undefined *)((int)piVar6 + 0xad) = 0;
      *(undefined2 *)(piVar6 + 0x29) = 0;
      *(undefined2 *)((int)piVar6 + 0xa6) = 0;
    }
    lbl_803DCB5C = lbl_803E5588;
    FUN_8002fc3c((double)lbl_803E5588,(double)lbl_803DC074);
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void dimcannon_hitDetect(void) {}
void dimcannon_release(void) {}
void dimcannon_initialise(void) {}

extern void objRenderFn_8003b8f4(f32 x);
extern f32 lbl_803E48E8;
extern f32 lbl_803E48F8;

#pragma scheduling off
#pragma peephole off
void dimcannon_render(int *obj, int p2, int p3, int p4, int p5, s8 visible) {
    u8 *def;
    u8 *sub;
    s16 saved;

    def = *(u8**)((char*)obj + 0x4c);
    if (*(s16*)((char*)obj + 0x46) == 0x1d6) {
        objRenderFn_8003b8f4(lbl_803E48E8);
    } else {
        sub = *(u8**)((char*)obj + 0xb8);
        saved = *(s16*)obj;
        *(s16*)obj = (s16)((s8)def[0x28] << 8);
        objRenderFn_8003b8f4(lbl_803E48E8);
        *(s16*)obj = saved;
        ObjPath_GetPointWorldPosition((int)obj, 0, (f32*)(sub + 0x8c), (f32*)(sub + 0x90), (f32*)(sub + 0x94), 0);
    }
}
#pragma peephole reset
#pragma scheduling reset
void dimlavasmash_free(void) {}
void dimlavasmash_hitDetect(void) {}

#pragma scheduling off
#pragma peephole off
void dimlavasmash_render(int *obj, int p2, int p3, int p4, int p5, s8 visible)
{
    u8 *state = *(u8 **)((char *)obj + 0xb8);
    if (state[2] == 2 && visible != 0) {
        objRenderFn_8003b8f4(lbl_803E48F8);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void dimlavasmash_update(int *obj) {
    extern int *gObjectTriggerInterface;
    u8 *sub;
    int *p;
    sub = *(u8**)((char*)obj + 0xb8);
    if (sub[2] == 1) {
        p = *(int**)((char*)obj + 0x54);
        *(s16*)((char*)p + 0x60) = (s16)(*(s16*)((char*)p + 0x60) & ~1);
    } else if (*(int*)((char*)obj + 0xf4) == 0) {
        if ((s8)sub[0] != -1) {
            ((void(*)(int, int*, int))((void**)*(int*)gObjectTriggerInterface)[18])((s8)sub[0], obj, -1);
        }
        *(int*)((char*)obj + 0xf4) = 1;
    }
}
#pragma peephole reset
#pragma scheduling reset

/* 8b "li r3, N; blr" returners. */
int dimlavasmash_getExtraSize(void) { return 0x3; }
int dimlavasmash_getObjectTypeId(void) { return 0x0; }

/* if (o->_X == K) return A; else return B; */
#pragma peephole off
#pragma scheduling off
#pragma peephole off
int dimcannon_getExtraSize(int *obj) { if (*(s16*)((char*)obj + 0x46) == 0x1d6) return 0xc; return 0xb4; }
int dimcannon_getObjectTypeId(int *obj) { if (*(s16*)((char*)obj + 0x46) == 0x1d6) return 0x0; return 0x0; }
#pragma peephole reset
#pragma scheduling reset
#pragma peephole reset

extern int ObjHits_GetPriorityHit(int obj, int *out, int *a, int *b);
extern void Sfx_PlayFromObject(int obj, int sfx);
extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z);
extern int mapGetBlock(void);
extern int mapBlockFn_800606ec(int arg1, int idx);
extern int mapBlockFn_80060678(void);
extern int fn_8006070C(int arg1, int idx);
extern int Shader_getLayer(int layer, int idx);

#pragma scheduling off
#pragma peephole off
/* Toggle collision/render surface flags for matching block polys and layers. */
void dimlavasmash_setBlockSurfaceFlags(int arg1, int arg2, int arg3)
{
    int i;
    int *block;
    int *layer;
    int got;
    for (i = 0; i < (int)*(u16 *)((char *)arg1 + 0x9a); i++) {
        block = (int *)mapBlockFn_800606ec(arg1, i);
        got = mapBlockFn_80060678();
        if (arg3 == got) {
            if (arg2 != 0) {
                block[0x10/4] = block[0x10/4] & ~2;
                block[0x10/4] = block[0x10/4] & ~1;
            } else {
                block[0x10/4] = block[0x10/4] | 2;
                block[0x10/4] = block[0x10/4] | 1;
            }
        }
    }
    for (i = 0; i < (int)*(u8 *)((char *)arg1 + 0xa2); i++) {
        layer = (int *)fn_8006070C(arg1, i);
        if (arg3 == (int)*(u8 *)((char *)Shader_getLayer((int)layer, 0) + 5)) {
            if (arg2 != 0) {
                layer[0x3c/4] = layer[0x3c/4] & ~2;
            } else {
                layer[0x3c/4] = layer[0x3c/4] | 2;
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int dimlavasmash_SeqFn(int obj, int p2, int *r5_arg)
{
    int *def;
    int hit;
    int block;
    int *state;
    state = *(int **)((char *)obj + 0xb8);
    def = *(int **)((char *)obj + 0x4c);
    if (*(u8 *)((char *)state + 2) == 0) {
        if (GameBit_Get(*(s16 *)((char *)def + 0x20)) != 0) {
            *(s16 *)((char *)*(int *)((char *)obj + 0x54) + 0x60) =
                (s16)(*(s16 *)((char *)*(int *)((char *)obj + 0x54) + 0x60) | 1);
            if (ObjHits_GetPriorityHit(obj, &hit, 0, 0) != 0) {
                if (*(s16 *)((char *)hit + 0x46) == 397) {
                    *(u8 *)((char *)state + 2) = 2;
                    Sfx_PlayFromObject(obj, SFXbaddie_eggsnatch_sniff1);
                    objPosToMapBlockIdx(*(f32 *)((char *)obj + 0xc),
                                        *(f32 *)((char *)obj + 0x10),
                                        *(f32 *)((char *)obj + 0x14));
                    block = mapGetBlock();
                    if ((void *)block != NULL) {
                        dimlavasmash_setBlockSurfaceFlags(block, 1, *(u8 *)((char *)state + 1));
                        dimlavasmash_setBlockSurfaceFlags(block, 0, *(u8 *)((char *)state + 1) + 1);
                    }
                }
            }
        }
    } else {
        if (*(u8 *)((char *)r5_arg + 0x80) == 1) {
            GameBit_Set(*(s16 *)((char *)def + 0x1e), 1);
            *(u8 *)((char *)state + 2) = 1;
        }
    }
    return *(u8 *)((char *)state + 2) == 0;
}
#pragma peephole reset
#pragma scheduling reset

extern int *gGameUIInterface;
extern void *lbl_803DDB50;
extern void Resource_Release(void *p);

#pragma scheduling off
#pragma peephole off
void dimcannon_free(int *obj) {
    if (*(s16 *)((char *)obj + 0x46) != 0x1d6) {
        ((void (*)(void))((int **)*gGameUIInterface)[0x18])();
        Resource_Release(lbl_803DDB50);
        lbl_803DDB50 = NULL;
    }
    ObjGroup_RemoveObject(obj, 3);
}
#pragma peephole reset
#pragma scheduling reset

extern void ObjMsg_AllocQueue(int *obj, int n);
extern int *Resource_Acquire(int a, int b);
extern int fn_801B2550(int *obj, int p2, char *p3);
extern f32 lbl_803E48B8;

/* EN v1.0 0x801B30C8  size: 628b  Dimcannon constructor: handles the 0x1d6
 * sub-variant, else seeds the 10-slot trail particle array, installs the
 * sequence fn, acquires its model resource and applies map flags. */
#pragma scheduling off
#pragma peephole off
void dimcannon_init(int *obj, int *arg)
{
    ObjMsg_AllocQueue(obj, 4);

    if (*(s16 *)((char *)obj + 0x46) == 0x1d6) {
        void *state;
        int *p;
        *(int *)((char *)obj + 0xf4) = 0;
        p = *(int **)((char *)obj + 0x64);
        if (p != 0) {
            *(int *)((char *)p + 0x30) |= 0xc10;
            p = *(int **)((char *)obj + 0x64);
            *(int *)((char *)p + 0x30) |= 0x8000;
        }
        state = *(void **)((char *)obj + 0xb8);
        *(s8 *)((char *)state + 0x9) = (s8)randomGetRange(-0x64, 0x64);
        *(s8 *)((char *)state + 0xa) = (s8)randomGetRange(-0x64, 0x64);
        *(s8 *)((char *)state + 0xb) = (s8)randomGetRange(-0x64, 0x64);
        *(u8 *)((char *)state + 0x7) = 1;
        p = *(int **)((char *)obj + 0x54);
        if (p != 0) {
            *(s16 *)((char *)p + 0xb2) = 1;
        }
        *(u16 *)((char *)obj + 0xb0) |= 0x4000;
    } else {
        void *state = *(void **)((char *)obj + 0xb8);
        u8 i;

        if (*(s8 *)((char *)obj + 0xac) == 0x13) {
            u8 v = 0;
            if (GameBit_Get(0xc17) && GameBit_Get(0xa21)) {
                v = 1;
            }
            *(u8 *)((char *)state + 0xb2) = v;
        }

        for (i = 0; i < 0xa; i += 5) {
            char *e = (char *)state + i * 4;
            *(f32 *)(e + 0x14) = *(f32 *)((char *)obj + 0xc);
            *(f32 *)(e + 0x3c) = *(f32 *)((char *)obj + 0x10);
            *(f32 *)(e + 0x64) = *(f32 *)((char *)obj + 0x14);
            *(f32 *)(e + 0x18) = *(f32 *)((char *)obj + 0xc);
            *(f32 *)(e + 0x40) = *(f32 *)((char *)obj + 0x10);
            *(f32 *)(e + 0x68) = *(f32 *)((char *)obj + 0x14);
            *(f32 *)(e + 0x1c) = *(f32 *)((char *)obj + 0xc);
            *(f32 *)(e + 0x44) = *(f32 *)((char *)obj + 0x10);
            *(f32 *)(e + 0x6c) = *(f32 *)((char *)obj + 0x14);
            *(f32 *)(e + 0x20) = *(f32 *)((char *)obj + 0xc);
            *(f32 *)(e + 0x48) = *(f32 *)((char *)obj + 0x10);
            *(f32 *)(e + 0x70) = *(f32 *)((char *)obj + 0x14);
            *(f32 *)(e + 0x24) = *(f32 *)((char *)obj + 0xc);
            *(f32 *)(e + 0x4c) = *(f32 *)((char *)obj + 0x10);
            *(f32 *)(e + 0x74) = *(f32 *)((char *)obj + 0x14);
        }

        *(u8 *)((char *)state + 0xaf) = 0x80;
        *(f32 *)((char *)state + 0x98) = lbl_803E48B8;
        *(u8 *)((char *)obj + 0xaf) |= 0x8;
        *(int *)((char *)obj + 0xbc) = (int)fn_801B2550;
        *(s16 *)((char *)obj + 0x0) = (s16)((s8)*(s8 *)((char *)arg + 0x28) << 8);
        lbl_803DDB50 = Resource_Acquire(0x79, 1);
        if (GameBit_Get(*(s16 *)((char *)arg + 0x1a))) {
            *(u8 *)((char *)state + 0xb0) = 0x3c;
            *(u8 *)((char *)state + 0xac) = 5;
        }
        *(f32 *)((char *)state + 0x8c) = *(f32 *)((char *)obj + 0xc);
        *(f32 *)((char *)state + 0x90) = *(f32 *)((char *)obj + 0x10);
        *(f32 *)((char *)state + 0x94) = *(f32 *)((char *)obj + 0x14);
    }

    *(u16 *)((char *)obj + 0xb0) |= 0x2000;
}
#pragma peephole reset
#pragma scheduling reset

extern void DIMwooddoor_updateFallingDebris(int *obj);
extern void DIMwooddoor_updateShardAim(int *obj, f32 a, f32 b, f32 c, f32 d);
extern void DIMwooddoor_spawnShard(int *obj, int p2);
extern f32  getXZDistance(f32 *a, f32 *b);
extern void ObjAnim_AdvanceCurrentMove(int *obj, f32 a, f32 b, int c);
extern void *Obj_GetPlayerObject(void);
extern void *fn_802972A8(void *player);
extern void buttonDisable(int chan, int mask);
extern u8  framesThisStep;
extern f32 timeDelta;
extern int *gCameraInterface;
extern int *gObjectTriggerInterface;
extern int lbl_803DBF10;
extern int lbl_803DBF0C;
extern f32 lbl_803E48EC;
extern f32 lbl_803E48F0;
extern f32 lbl_803DBEF4;

/* EN v1.0 0x801B2C68  size: 1120b  Dimcannon per-frame state machine: idle ->
 * tracking -> firing -> spent, plus the 0x1d6 falling-debris sub-variant. */
#pragma scheduling off
#pragma peephole off
void dimcannon_update(int *obj)
{
    char *state;
    void *player;
    int *src = *(int **)((char *)obj + 0x4c);

    if (*(s16 *)((char *)obj + 0x46) == 0x1d6) {
        DIMwooddoor_updateFallingDebris(obj);
        return;
    }

    if ((*(u8 *)((char *)obj + 0xaf) & 0x8) && GameBit_Get(*(s16 *)((char *)src + 0x1a))) {
        *(u8 *)((char *)obj + 0xaf) = (u8)(*(u8 *)((char *)obj + 0xaf) & ~0x8);
    }

    state = *(char **)((char *)obj + 0xb8);
    player = Obj_GetPlayerObject();
    if (fn_802972A8(player) != 0) {
        *(int *)(state + 0x0) = 0;
    } else {
        *(void **)(state + 0x0) = player;
    }

    *(s16 *)((char *)obj + 0x6) = (s16)(*(s16 *)((char *)obj + 0x6) & ~0x4000);

    switch (*(u8 *)(state + 0xac)) {
    case 0:
        if (GameBit_Get(*(s16 *)((char *)src + 0x1c))) {
            *(u8 *)(state + 0xac) = 4;
        }
        break;
    case 5: {
        s8 t = *(s8 *)(state + 0xb0);
        if (t > 0) {
            *(s8 *)(state + 0xb0) = (s8)(t - framesThisStep);
        } else if (*(u8 *)((char *)obj + 0xaf) & 0x1) {
            int *focusObj;
            *(u8 *)(state + 0xae) = 0;
            *(u8 *)(state + 0xb1) = 0;
            focusObj = obj;
            (*(void (**)(int, int, int, int, int **, int, int))(*(int *)gCameraInterface + 0x1c))(
                0x51, 1, 0, 4, &focusObj, 0x32, 0xff);
            buttonDisable(0, 0x100);
            *(u8 *)(state + 0xac) = 3;
            (*(void (**)(int, int *, int))(*(int *)gObjectTriggerInterface + 0x48))(0, obj, -1);
            *(u8 *)(state + 0xb0) = 0x3c;
            *(u8 *)((char *)obj + 0xaf) |= 0x8;
        }
        *(u8 *)(state + 0xad) = 0;
        *(s16 *)(state + 0xa4) = 0;
        *(s16 *)(state + 0xa6) = 0;
        break;
    }
    case 4:
        DIMwooddoor_updateShardAim(obj, *(f32 *)(state + 0x4), *(f32 *)(state + 0x8),
                                   *(f32 *)(state + 0xc), *(f32 *)(state + 0x10));
        if (GameBit_Get(*(s16 *)((char *)src + 0x1a))) {
            *(u8 *)(state + 0xac) = 5;
        } else if (*(void **)(state + 0x0) != 0 && !GameBit_Get(*(s16 *)((char *)src + 0x1e))) {
            f32 d = getXZDistance((f32 *)((char *)obj + 0x18),
                                  (f32 *)(*(char **)(state + 0x0) + 0x18));
            int v = *(s16 *)((char *)src + 0x26) * lbl_803DBF10;
            if (d < (f32)v / lbl_803E48EC) {
                *(u8 *)(state + 0xac) = 1;
            }
        }
        *(u8 *)(state + 0xad) = 0;
        *(s16 *)(state + 0xa4) = 0;
        *(s16 *)(state + 0xa6) = 0;
        break;
    case 1:
        if (GameBit_Get(*(s16 *)((char *)src + 0x1a))) {
            *(u8 *)(state + 0xac) = 5;
            break;
        }
        if (GameBit_Get(*(s16 *)((char *)src + 0x1e))) {
            *(u8 *)(state + 0xac) = 4;
            break;
        }
        if (*(void **)(state + 0x0) != 0) {
        *(u8 *)(state + 0xaf) += framesThisStep;
        if (*(u8 *)(state + 0xaf) > 0xa) {
            u8 j;
            *(u8 *)(state + 0xaf) = 0;
            for (j = 0; j < 9; j++) {
                char *e = state + j * 4;
                *(f32 *)(e + 0x14) = *(f32 *)(e + 0x18);
                *(f32 *)(e + 0x3c) = *(f32 *)(e + 0x40);
                *(f32 *)(e + 0x64) = *(f32 *)(e + 0x68);
                if (j == 0 || *(f32 *)(e + 0x3c) > *(f32 *)(state + 0x8)) {
                    *(f32 *)(state + 0x8) = *(f32 *)(e + 0x3c);
                }
            }
            *(f32 *)(state + 0x38) = *(f32 *)(*(char **)(state + 0x0) + 0xc);
            *(f32 *)(state + 0x60) = *(f32 *)(*(char **)(state + 0x0) + 0x10);
            *(f32 *)(state + 0x88) = *(f32 *)(*(char **)(state + 0x0) + 0x14);
            *(f32 *)(state + 0x4) = *(f32 *)(state + 0x14);
            *(f32 *)(state + 0xc) = *(f32 *)(state + 0x64);
        }
        if (*(s16 *)(state + 0xa4) > 0) {
            *(s16 *)(state + 0xa4) = (s16)(*(s16 *)(state + 0xa4) - framesThisStep);
        }
        if (*(s16 *)(state + 0xa6) > 0) {
            *(s16 *)(state + 0xa6) = (s16)(*(s16 *)(state + 0xa6) - framesThisStep);
        }
        *(f32 *)(state + 0x10) = getXZDistance((f32 *)((char *)obj + 0x18),
                                               (f32 *)(*(char **)(state + 0x0) + 0x18));
        DIMwooddoor_updateShardAim(obj, *(f32 *)(state + 0x4), *(f32 *)(state + 0x8),
                                   *(f32 *)(state + 0xc), *(f32 *)(state + 0x10));
        DIMwooddoor_spawnShard(obj, 0);
        {
            f32 d2 = *(f32 *)(state + 0x10);
            int v = *(s16 *)((char *)src + 0x26) * lbl_803DBF0C;
            if (d2 > (f32)v / lbl_803E48EC) {
                *(u8 *)(state + 0xac) = 4;
            }
        }
        } else {
            *(u8 *)(state + 0xac) = 4;
        }
        break;
    }

    lbl_803DBEF4 = lbl_803E48F0;
    ObjAnim_AdvanceCurrentMove(obj, lbl_803E48F0, timeDelta, 0);
}
#pragma peephole reset
#pragma scheduling reset

extern void setAButtonIcon(int icon);
extern void setBButtonIcon(int icon);
extern void hudFn_8011f38c(int v);
extern s16 *objModelGetVecFn_800395d8(int *obj, int p2);
extern s8   padGetStickX(int chan);
extern int  fn_80296A14(void *player);
extern void playerAddRemoveMagic(void *player, int amount);
extern u32  getButtonsJustPressed(int chan);
extern u32  getButtonsHeld(int chan);
extern u32  getButtonsJustPressedIfNotBusy(int chan);
extern int  Sfx_IsPlayingFromObjectChannel(int *obj, int channel);
extern void Sfx_StopObjectChannel(int *obj, int channel);
extern void Sfx_KeepAliveLoopedObjectSound(int *obj, int id);

extern int *gGameUIInterface;
extern u8  lbl_803DBF00;
extern s16 lbl_803DBF02;
extern s16 lbl_803DBF04;
extern f32 lbl_803DBF08;
extern f32 lbl_803DBEF8;
extern f32 lbl_803DBEFC;

/* EN v1.0 0x801B2550  size: 1504b  Dimcannon manned-control sequence: aims the
 * turret with the stick, charges with A, fires on release/full charge, and
 * exits on B or after the post-completion delay. */
#pragma scheduling off
#pragma peephole off
int fn_801B2550(int *obj, int p2, char *p3)
{
    int *src = *(int **)((char *)obj + 0x4c);
    char *state;
    int camMode;
    u8 done = 0;
    void *player;

    *(u8 *)(p3 + 0x56) = 0;
    *(s16 *)(p3 + 0x6e) = (s16)(*(s16 *)(p3 + 0x6e) & ~0x608);
    state = *(char **)((char *)obj + 0xb8);

    if (*(u8 *)(state + 0xac) == 0x3) {
        s16 *vec;
        s8 timer;
        int delta;

        player = Obj_GetPlayerObject();
        setAButtonIcon(0x16);
        setBButtonIcon(0x17);
        hudFn_8011f38c(1);
        camMode = (*(int (**)(void))(*(int *)gCameraInterface + 0x10))();
        if (camMode != 0x51 && camMode != 0x4c) {
            int *focusObj = obj;
            (*(void (**)(int, int, int, int, int **, int, int))(*(int *)gCameraInterface + 0x1c))(
                0x51, 1, 0, 4, &focusObj, 0x32, 0xff);
        }
        if (camMode != 0x51) {
            return 0;
        }
        vec = objModelGetVecFn_800395d8(obj, 0);
        timer = *(s8 *)(state + 0xb0);
        if (timer > 0) {
            *(s8 *)(state + 0xb0) = (s8)(timer - framesThisStep);
            if (*(s8 *)(state + 0xb0) <= 0) {
                (*(void (**)(int, int))(*(int *)gGameUIInterface + 0x58))(lbl_803DBF00, 0x5d5);
            }
        } else {
            if (!GameBit_Get(0xdb)) {
                (*(void (**)(int, int, int, int))(*(int *)gGameUIInterface + 0x38))(0x4b9, 0x14, 0x8c, 1);
                GameBit_Set(0xdb, 1);
            }
            delta = (int)(-lbl_803DBF08 * (f32)padGetStickX(0));
            if (delta != 0) {
                s16 cur = *(s16 *)((char *)vec + 0x2);
                s16 mag = cur < 0 ? -cur : cur;
                if (mag > lbl_803DBF02 - lbl_803DBF04) {
                    int sd, sc;
                    if (delta < 0) sd = -1;
                    else if (delta > 0) sd = 1;
                    else sd = 0;
                    if (cur < 0) sc = -1;
                    else if (cur > 0) sc = 1;
                    else sc = 0;
                    if (sc == sd) {
                        delta = delta * (lbl_803DBF02 - mag) / lbl_803DBF04;
                    }
                }
                *(s16 *)((char *)vec + 0x2) = (s16)(*(s16 *)((char *)vec + 0x2) + delta);
                Sfx_KeepAliveLoopedObjectSound(obj, 0x1ff);
            } else {
                if (*(int *)(state + 0xa8) != 0) {
                    Sfx_PlayFromObject((int)obj, 0x1fe);
                }
            }
            *(int *)(state + 0xa8) = delta;
            if (*(s16 *)(state + 0xa4) > 0) {
                *(s16 *)(state + 0xa4) = (s16)(*(s16 *)(state + 0xa4) - framesThisStep);
            }
            if (*(s16 *)(state + 0xa6) > 0) {
                *(s16 *)(state + 0xa6) = (s16)(*(s16 *)(state + 0xa6) - framesThisStep);
            }
            if ((getButtonsHeld(0) & 0x100) && *(s16 *)(state + 0xa4) <= 0) {
                buttonDisable(0, 0x100);
                if (fn_80296A14(player) >= 1) {
                    *(u8 *)(state + 0xae) += framesThisStep;
                    Sfx_KeepAliveLoopedObjectSound(obj, 0x9a);
                    if (Sfx_IsPlayingFromObjectChannel(obj, 2) == 0) {
                        Sfx_PlayFromObject((int)obj, 0x201);
                        Sfx_PlayFromObject((int)obj, 0x202);
                    }
                } else {
                    Sfx_PlayFromObject((int)obj, 0x40c);
                }
            } else {
                Sfx_StopObjectChannel(obj, 2);
            }
            if (*(u8 *)(state + 0xae) > lbl_803DBF00) {
                *(u8 *)(state + 0xae) = lbl_803DBF00;
            }
            (*(void (**)(int))(*(int *)gGameUIInterface + 0x5c))(*(u8 *)(state + 0xae));
            *(f32 *)(state + 0x98) = (f32)*(u8 *)(state + 0xae) * lbl_803DBEFC + lbl_803DBEF8;
            if ((getButtonsJustPressedIfNotBusy(0) & 0x100) ||
                *(u8 *)(state + 0xae) == lbl_803DBF00) {
                if (*(s16 *)(state + 0xa4) <= 0 && fn_80296A14(player) >= 1) {
                    buttonDisable(0, 0x100);
                    playerAddRemoveMagic(player, -1);
                    *(u8 *)(state + 0xad) = 1;
                    *(u8 *)(state + 0xae) = 0;
                }
            }
            DIMwooddoor_spawnShard(obj, 1);
            if (*(s8 *)((char *)obj + 0xac) == 0x13 && *(u8 *)(state + 0xb2) == 0 &&
                GameBit_Get(0xc17) && GameBit_Get(0xa21)) {
                *(u8 *)(state + 0xb2) = 1;
                *(u8 *)(state + 0xb1) = 1;
            }
            {
                u8 b1 = *(u8 *)(state + 0xb1);
                if (b1 != 0) {
                    *(u8 *)(state + 0xb1) = (u8)(b1 + framesThisStep);
                    if (*(u8 *)(state + 0xb1) > 0x3c) {
                        done = 1;
                    }
                }
            }
            if (done != 0 || (getButtonsJustPressed(0) & 0x200)) {
                buttonDisable(0, 0x200);
                hudFn_8011f38c(0);
                (*(void (**)(void))(*(int *)gGameUIInterface + 0x60))();
                (*(void (**)(int, int, int, int, int, int, int))(*(int *)gCameraInterface + 0x1c))(
                    0x42, 0, 1, 0, 0, 0, 0xff);
                *(u8 *)(state + 0xac) = 5;
                *(u8 *)(state + 0xb0) = 0x3c;
                *(u8 *)(p3 + 0x90) |= 0x4;
                *(u8 *)((char *)obj + 0xaf) = (u8)(*(u8 *)((char *)obj + 0xaf) & ~0x8);
                if (Sfx_IsPlayingFromObjectChannel(obj, 8) != 0) {
                    Sfx_IsPlayingFromObjectChannel(obj, 0);
                }
                Sfx_StopObjectChannel(obj, 2);
            }
            ObjAnim_AdvanceCurrentMove(obj, lbl_803DBEF4, timeDelta, 0);
        }
    } else {
        s16 *vec2;
        *(s16 *)((char *)obj + 0x6) = (s16)(*(s16 *)((char *)obj + 0x6) & ~0x4000);
        vec2 = objModelGetVecFn_800395d8(obj, 0);
        *(s16 *)((char *)vec2 + 0x2) =
            (s16)(*(s16 *)((char *)obj + 0x0) - ((s8)*(s8 *)((char *)src + 0x28) << 8));
        *(s16 *)((char *)obj + 0x0) = (s16)((s8)*(s8 *)((char *)src + 0x28) << 8);
        *(u8 *)(state + 0xac) = 4;
    }

    return 0;
}
#pragma peephole reset
#pragma scheduling reset
