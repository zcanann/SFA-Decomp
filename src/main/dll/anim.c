#include "ghidra_import.h"
#include "main/audio/sfx_ids.h"
#include "main/mapEventTypes.h"
#include "main/dll/anim.h"

#pragma peephole off
#pragma scheduling off
extern undefined4 FUN_800033a8();
extern undefined8 FUN_80003494();
extern undefined4 getLActions();
extern undefined4 FUN_800067c0();
extern bool FUN_800067f0();
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern void* FUN_800069a8();
extern int FUN_80006a10();
extern int FUN_80006a64();
extern undefined8 FUN_80006a68();
extern uint FUN_80006ab0();
extern uint FUN_80006ab8();
extern undefined4 FUN_80006ac0();
extern undefined8 FUN_80006ac4();
extern undefined8 FUN_80006ac8();
extern undefined4 FUN_80006acc();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern uint FUN_80006c00();
extern undefined4 FUN_80017688();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern undefined4 FUN_80017710();
extern double FUN_80017714();
extern undefined4 FUN_8001771c();
extern uint FUN_80017758();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017784();
extern undefined4 FUN_80017a5c();
extern undefined4 FUN_80017a88();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80017ad0();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 FUN_8002f6ac();
extern undefined8 FUN_800305f8();
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHit();
extern uint ObjGroup_ContainsObject();
extern int ObjGroup_FindNearestObjectForObject();
extern int ObjGroup_FindNearestObject();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToObjects();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern undefined4 ObjPath_GetPointWorldPosition();
extern int Obj_GetYawDeltaToObject();
extern void* FUN_80039518();
extern undefined4 FUN_8003964c();
extern undefined4 FUN_8003b540();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined4 FUN_80044404();
extern undefined4 FUN_80053c98();
extern undefined4 FUN_80057690();
extern undefined4 FUN_8005b024();
extern int FUN_8005b398();
extern uint FUN_8005b54c();
extern undefined4 FUN_800723a0();
extern undefined4 FUN_800810f4();
extern undefined4 FUN_8008110c();
extern undefined4 FUN_8008111c();
extern undefined8 FUN_80081120();
extern undefined4 FUN_80135814();
extern undefined4 SH_LevelControl_runBloopEvent();
extern undefined4 FUN_801d8480();
extern undefined4 FUN_801fe3b0();
extern undefined4 FUN_801fe540();
extern int FUN_801fe750();
extern undefined4 FUN_801fe924();
extern undefined4 FUN_8020a488();
extern undefined4 FUN_80247eb8();
extern undefined4 FUN_80247edc();
extern undefined4 FUN_80247ef8();
extern double SeekTwiceBeforeRead();
extern undefined8 FUN_80286830();
extern undefined8 FUN_80286834();
extern undefined8 FUN_80286838();
extern undefined8 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern undefined4 FUN_80294c44();
extern undefined4 FUN_80294d60();
extern undefined4 SUB42();

extern undefined4 DAT_802c2c90;
extern undefined4 DAT_802c2c94;
extern undefined4 DAT_802c2c98;
extern undefined4 DAT_802c2c9c;
extern undefined4 DAT_8032a158;
extern undefined4 DAT_8032a274;
extern undefined4 DAT_8032a280;
extern undefined4 DAT_8032a284;
extern undefined4 DAT_8032a290;
extern undefined4 DAT_8032a2a4;
extern undefined4 DAT_8032a31c;
extern undefined4 DAT_8032a33c;
extern undefined4 DAT_8032a34c;
extern undefined4 DAT_8032a35c;
extern undefined4 DAT_8032a36c;
extern undefined4 DAT_8032a37c;
extern undefined4 DAT_8032a38c;
extern undefined2 DAT_8032a488;
extern undefined4 DAT_8032a494;
extern undefined4 DAT_8032a496;
extern undefined4 DAT_8032a498;
extern undefined4 DAT_803add20;
extern undefined4 DAT_803add2c;
extern undefined4 DAT_803add30;
extern undefined4 DAT_803add34;
extern undefined4 DAT_803add38;
extern undefined4 DAT_803add3c;
extern undefined4 DAT_803add40;
extern undefined4 DAT_803add44;
extern undefined4 DAT_803add48;
extern undefined4 DAT_803add4c;
extern undefined4 DAT_803add50;
extern undefined4 DAT_803add54;
extern undefined4 DAT_803add58;
extern undefined4 DAT_803add5c;
extern undefined4 DAT_803add60;
extern undefined4 DAT_803add64;
extern undefined4 DAT_803add68;
extern undefined4 DAT_803add6c;
extern undefined4 DAT_803add70;
extern undefined4 DAT_803add74;
extern undefined4 DAT_803add78;
extern undefined4 DAT_803add7c;
extern undefined4 DAT_803add80;
extern undefined4 DAT_803add84;
extern undefined4 DAT_803add88;
extern undefined4 DAT_803add8c;
extern undefined4 DAT_803add90;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dcdd8;
extern undefined4 DAT_803dcde0;
extern undefined4 DAT_803dcde8;
extern undefined4 DAT_803dcdea;
extern undefined4 DAT_803dcdeb;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd6fc;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd718;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803dd72c;
extern undefined4* DAT_803dd738;
extern undefined4 DAT_803de960;
extern undefined4 DAT_803de968;
extern undefined4 DAT_803e6e58;
extern undefined4 DAT_803e6e5c;
extern f64 DOUBLE_803e6ea8;
extern f64 DOUBLE_803e6f78;
extern f64 DOUBLE_803e7000;
extern f64 DOUBLE_803e7048;
extern f64 DOUBLE_803e7058;
extern f32 lbl_803DC074;
extern f32 lbl_803DC078;
extern f32 lbl_803DCDC8;
extern f32 lbl_803DCDCC;
extern f32 lbl_803DCDD0;
extern f32 lbl_803DCDD4;
extern f32 playerMapOffsetZ;
extern f32 lbl_803E6E60;
extern f32 lbl_803E6E64;
extern f32 lbl_803E6E7C;
extern f32 lbl_803E6E84;
extern f32 lbl_803E6E98;
extern f32 lbl_803E6EB8;
extern f32 lbl_803E6EBC;
extern f32 lbl_803E6EC0;
extern f32 lbl_803E6EC4;
extern f32 lbl_803E6EC8;
extern f32 lbl_803E6ECC;
extern f32 lbl_803E6ED0;
extern f32 lbl_803E6ED4;
extern f32 lbl_803E6ED8;
extern f32 lbl_803E6EDC;
extern f32 lbl_803E6EE0;
extern f32 lbl_803E6EE4;
extern f32 lbl_803E6EE8;
extern f32 lbl_803E6EEC;
extern f32 lbl_803E6EF0;
extern f32 lbl_803E6EF4;
extern f32 lbl_803E6EF8;
extern f32 lbl_803E6EFC;
extern f32 lbl_803E6F00;
extern f32 lbl_803E6F08;
extern f32 lbl_803E6F0C;
extern f32 lbl_803E6F14;
extern f32 lbl_803E6F18;
extern f32 lbl_803E6F1C;
extern f32 lbl_803E6F20;
extern f32 lbl_803E6F2C;
extern f32 lbl_803E6F38;
extern f32 lbl_803E6F40;
extern f32 lbl_803E6F44;
extern f32 lbl_803E6F48;
extern f32 lbl_803E6F4C;
extern f32 lbl_803E6F50;
extern f32 lbl_803E6F58;
extern f32 lbl_803E6F5C;
extern f32 lbl_803E6F60;
extern f32 lbl_803E6F64;
extern f32 lbl_803E6F68;
extern f32 lbl_803E6F6C;
extern f32 lbl_803E6F70;
extern f32 lbl_803E6F80;
extern f32 lbl_803E6F84;
extern f32 lbl_803E6F88;
extern f32 lbl_803E6F8C;
extern f32 lbl_803E6F90;
extern f32 lbl_803E6F94;
extern f32 lbl_803E6F98;
extern f32 lbl_803E6F9C;
extern f32 lbl_803E6FA0;
extern f32 lbl_803E6FA4;
extern f32 lbl_803E6FA8;
extern f32 lbl_803E6FAC;
extern f32 lbl_803E6FB0;
extern f32 lbl_803E6FB4;
extern f32 lbl_803E6FB8;
extern f32 lbl_803E6FBC;
extern f32 lbl_803E6FC0;
extern f32 lbl_803E6FC4;
extern f32 lbl_803E6FC8;
extern f32 lbl_803E6FCC;
extern f32 lbl_803E6FD0;
extern f32 lbl_803E6FD4;
extern f32 lbl_803E6FD8;
extern f32 lbl_803E6FDC;
extern f32 lbl_803E6FE0;
extern f32 lbl_803E6FE4;
extern f32 lbl_803E6FE8;
extern f32 lbl_803E6FEC;
extern f32 lbl_803E6FF0;
extern f32 lbl_803E6FF4;
extern f32 lbl_803E7008;
extern f32 lbl_803E700C;
extern f32 lbl_803E7010;
extern f32 lbl_803E7014;
extern f32 lbl_803E7018;
extern f32 lbl_803E701C;
extern f32 lbl_803E7020;
extern f32 lbl_803E7034;
extern f32 lbl_803E7038;
extern f32 lbl_803E703C;
extern f32 lbl_803E7040;
extern f32 lbl_803E7060;
extern f32 lbl_803E7064;
extern f32 lbl_803E7068;
extern f32 lbl_803E706C;
extern f32 lbl_803E7070;
extern f32 lbl_803E7074;
extern f32 lbl_803E7078;
extern undefined4 PTR_DAT_8032a154;


#pragma scheduling off
#pragma peephole off
int GCRobotBlast_SeqFn(int obj, int unused, int p3)
{
  extern void objfx_spawnDirectionalBurst(int, int, f32, int, int, int, f32, int, int);
  extern f32 lbl_803E6270;
  extern f32 lbl_803E6274;
  typedef struct {
    u8 b80 : 1;
  } BlastFlags4;
  int sub = *(int *)(obj + 0xb8);
  int i;

  for (i = 0; i < *(u8 *)(p3 + 0x8b); i++) {
    ((BlastFlags4 *)(sub + 4))->b80 = *(u8 *)(p3 + i + 0x81);
  }
  if (((u32)*(u8 *)(sub + 4) >> 7 & 1) != 0) {
    switch (*(int *)sub) {
    case 0:
    case 1:
      objfx_spawnDirectionalBurst(obj, 7, lbl_803E6270, 5, 6, 0x64, lbl_803E6274, 0, 0x200000);
      objfx_spawnDirectionalBurst(obj, 6, lbl_803E6270, 1, 6, 0x64, lbl_803E6274, 0, 0x200000);
      break;
    }
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_801ff8b8
 * EN v1.0 Address: 0x801FF8B8
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x801FFE60
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ff8b8(short *param_1)
{
  int iVar1;
  
  FUN_801fe540(param_1,*(undefined4 **)(param_1 + 0x5c));
  ObjMsg_AllocQueue((int)param_1,8);
  iVar1 = *(int *)(param_1 + 0x32);
  if (iVar1 != 0) {
    *(uint *)(iVar1 + 0x30) = *(uint *)(iVar1 + 0x30) | 0x4008;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ff90c
 * EN v1.0 Address: 0x801FF90C
 * EN v1.0 Size: 212b
 * EN v1.1 Address: 0x801FFEBC
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801ff90c(int param_1,undefined4 param_2,int param_3)
{
  int *piVar1;
  int iVar2;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar2 = iVar2 + 1) {
    *(byte *)(piVar1 + 1) = *(char *)(param_3 + iVar2 + 0x81) << 7 | *(byte *)(piVar1 + 1) & 0x7f;
  }
  if (((*(char *)(piVar1 + 1) < '\0') && (*piVar1 < 2)) && (-1 < *piVar1)) {
    FUN_800810f4((double)lbl_803E6F08,(double)lbl_803E6F0C,param_1,7,5,6,100,0,0x200000);
    FUN_800810f4((double)lbl_803E6F08,(double)lbl_803E6F0C,param_1,6,1,6,100,0,0x200000);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801ff9e0
 * EN v1.0 Address: 0x801FF9E0
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x80200014
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ff9e0(int param_1)
{
  char cVar1;
  
  cVar1 = *(char *)(*(int *)(param_1 + 0xb8) + 8);
  if ((cVar1 != '\0') && (cVar1 != '\x04')) {
    FUN_8003b818(param_1);
  }
  return;
}


/*
 * --INFO--
 *
 * Function: FUN_801ffe30
 * EN v1.0 Address: 0x801FFE30
 * EN v1.0 Size: 148b
 * EN v1.1 Address: 0x802003B4
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ffe30(int param_1,int param_2)
{
  float fVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  *(undefined *)(iVar3 + 8) = 5;
  *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_2 + 8);
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_2 + 0xc);
  *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(param_2 + 0x10);
  fVar1 = lbl_803E6F14;
  *(float *)(param_1 + 0x2c) = lbl_803E6F14;
  *(float *)(param_1 + 0x24) = fVar1;
  *(float *)(param_1 + 0x28) = lbl_803E6F38;
  uVar2 = randomGetRange(0,0xffff);
  *(uint *)(iVar3 + 4) = uVar2;
  uVar2 = FUN_80017690((int)*(short *)(param_2 + 0x20));
  if (uVar2 != 0) {
    *(undefined *)(iVar3 + 8) = 4;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ffec4
 * EN v1.0 Address: 0x801FFEC4
 * EN v1.0 Size: 728b
 * EN v1.1 Address: 0x80200450
 * EN v1.1 Size: 624b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ffec4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  short sVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  undefined8 extraout_f1;
  undefined8 uVar10;
  float local_28 [10];
  
  uVar10 = FUN_80286838();
  iVar4 = (int)((ulonglong)uVar10 >> 0x20);
  iVar5 = (int)uVar10;
  iVar8 = *(int *)(iVar4 + 0x4c);
  local_28[0] = lbl_803E6F44;
  iVar9 = *(int *)(*(int *)(iVar4 + 0xb8) + 0x40c);
  if ((*(char *)(iVar5 + 0x27b) == '\0') && (*(char *)(iVar9 + 0x34) == '\0')) {
    iVar8 = *(int *)(iVar9 + 0x2c);
    if (iVar8 == 1) {
      if (*(int *)(iVar5 + 0x2d0) == 0) {
        *(undefined *)(iVar9 + 0x34) = 1;
      }
    }
    else if ((iVar8 < 1) && (-1 < iVar8)) {
      if (*(int *)(iVar5 + 0x2d0) == 0) {
        *(undefined *)(iVar9 + 0x34) = 1;
      }
      else if ((*(int *)(iVar9 + 0x30) != 0) &&
              (uVar2 = ObjGroup_ContainsObject(*(int *)(iVar5 + 0x2d0),*(int *)(iVar9 + 0x30)), uVar2 == 0)) {
        uVar3 = ObjGroup_FindNearestObjectForObject(*(undefined4 *)(iVar9 + 0x30),iVar4,(float *)0x0);
        *(undefined4 *)(iVar5 + 0x2d0) = uVar3;
        if (*(int *)(iVar5 + 0x2d0) == 0) {
          *(undefined *)(iVar9 + 0x34) = 1;
        }
        *(float *)(iVar5 + 0x280) = lbl_803E6F40;
      }
    }
    if (((*(short *)(iVar9 + 0x1c) == -1) && (*(int *)(iVar9 + 0x3c) != 0)) &&
       (iVar4 = (**(code **)(**(int **)(*(int *)(iVar9 + 0x3c) + 0x68) + 0x20))(), iVar4 == 0)) {
      *(undefined4 *)(iVar9 + 0x3c) = 0;
      *(undefined *)(iVar9 + 0x34) = 1;
    }
  }
  else {
    *(byte *)(iVar9 + 0x15) = *(byte *)(iVar9 + 0x15) & 0xfb;
    *(undefined *)(iVar9 + 0x34) = 0;
    uVar10 = extraout_f1;
    uVar2 = FUN_80006ab0(*(short **)(iVar9 + 0x24));
    if (uVar2 == 0) {
      FUN_80006ac0(*(short **)(iVar9 + 0x24),iVar9 + 0x28);
    }
    else {
      if (*(int *)(iVar8 + 0x14) == -1) {
        FUN_80017ac8(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4);
        goto LAB_802006a8;
      }
      sVar1 = *(short *)(iVar8 + 0x24);
      iVar6 = (int)*(short *)(&DAT_8032a158 + sVar1 * 8);
      iVar7 = iVar6 * 0xc;
      for (; iVar6 != 0; iVar6 = iVar6 + -1) {
        iVar7 = iVar7 + -0xc;
        FUN_80006ac4(*(short **)(iVar9 + 0x24),(uint)((&PTR_DAT_8032a154)[sVar1 * 2] + iVar7));
      }
      *(undefined *)(iVar9 + 0x34) = 1;
      *(undefined4 *)(iVar4 + 0xc) = *(undefined4 *)(iVar8 + 8);
      *(undefined4 *)(iVar4 + 0x10) = *(undefined4 *)(iVar8 + 0xc);
      *(undefined4 *)(iVar4 + 0x14) = *(undefined4 *)(iVar8 + 0x10);
    }
    iVar8 = *(int *)(iVar9 + 0x2c);
    if (iVar8 == 1) {
      *(undefined4 *)(iVar5 + 0x2d0) = *(undefined4 *)(iVar9 + 0x30);
    }
    else if (((iVar8 < 1) && (-1 < iVar8)) && (*(int *)(iVar9 + 0x30) != 0)) {
      uVar3 = ObjGroup_FindNearestObjectForObject(*(int *)(iVar9 + 0x30),iVar4,local_28);
      *(undefined4 *)(iVar5 + 0x2d0) = uVar3;
    }
    if (*(int *)(iVar5 + 0x2d0) != 0) {
      (**(code **)(*DAT_803dd70c + 0x14))(iVar4,iVar5,*(undefined4 *)(iVar9 + 0x28));
    }
  }
LAB_802006a8:
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8020019c
 * EN v1.0 Address: 0x8020019C
 * EN v1.0 Size: 624b
 * EN v1.1 Address: 0x802006C0
 * EN v1.1 Size: 572b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020019c(void)
{
  int iVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined4 *puVar8;
  undefined8 uVar9;
  float local_28;
  undefined auStack_24 [36];
  
  uVar9 = FUN_80286840();
  iVar2 = (int)((ulonglong)uVar9 >> 0x20);
  iVar6 = (int)uVar9;
  iVar7 = *(int *)(iVar2 + 0x4c);
  local_28 = lbl_803E6F44;
  puVar8 = *(undefined4 **)(*(int *)(iVar2 + 0xb8) + 0x40c);
  if ((*(char *)(iVar6 + 0x27b) == '\0') && ((*(byte *)(puVar8 + 0x11) >> 6 & 1) == 0)) {
    if ((puVar8[6] == 0) && (lbl_803E6F48 < (float)puVar8[0xe])) {
      puVar8[0xe] = (float)puVar8[0xe] - lbl_803E6F48;
      local_28 = lbl_803E6F4C;
      iVar1 = 3;
      puVar8 = (undefined4 *)0x8032a348;
      iVar7 = 0;
      while( true ) {
        puVar8 = puVar8 + -1;
        iVar1 = iVar1 + -1;
        if (iVar1 < 0) break;
        iVar5 = ObjGroup_FindNearestObjectForObject(*puVar8,iVar2,&local_28);
        if (iVar5 != 0) {
          iVar7 = iVar5;
        }
      }
      *(int *)(iVar6 + 0x2d0) = iVar7;
      if (iVar7 != 0) {
        if (lbl_803E6F50 <= local_28) {
          (**(code **)(*DAT_803dd70c + 0x14))(iVar2,iVar6,4);
        }
        else {
          (**(code **)(*DAT_803dd70c + 0x14))(iVar2,iVar6,2);
        }
      }
    }
  }
  else {
    *(byte *)((int)puVar8 + 0x15) = *(byte *)((int)puVar8 + 0x15) & 0xfb;
    *(byte *)(puVar8 + 0x11) = *(byte *)(puVar8 + 0x11) & 0xbf;
    uVar3 = FUN_80006ab0((short *)puVar8[9]);
    if (uVar3 == 0) {
      FUN_80006ac0((short *)puVar8[9],(uint)auStack_24);
    }
    iVar1 = puVar8[8] - *(int *)*puVar8;
    iVar1 = iVar1 / 0xc + (iVar1 >> 0x1f);
    if ((int)*(short *)((int *)*puVar8 + 1) <= iVar1 - (iVar1 >> 0x1f)) {
      puVar8[8] = 0;
    }
    if (puVar8[8] == 0) {
      puVar8[8] = *(undefined4 *)*puVar8;
      *(undefined4 *)(iVar2 + 0xc) = *(undefined4 *)(iVar7 + 8);
      *(undefined4 *)(iVar2 + 0x10) = *(undefined4 *)(iVar7 + 0xc);
      *(undefined4 *)(iVar2 + 0x14) = *(undefined4 *)(iVar7 + 0x10);
    }
    if (*(int *)(puVar8[8] + 4) != 0) {
      uVar4 = ObjGroup_FindNearestObjectForObject(*(int *)(puVar8[8] + 4),iVar2,&local_28);
      *(undefined4 *)(iVar6 + 0x2d0) = uVar4;
    }
    if (*(int *)(iVar6 + 0x2d0) != 0) {
      (**(code **)(*DAT_803dd70c + 0x14))(iVar2,iVar6,*(undefined4 *)puVar8[8]);
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8020040c
 * EN v1.0 Address: 0x8020040C
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x802008FC
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020040c(int param_1,int param_2)
{
  float fVar1;
  int iVar2;

  iVar2 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,1);
    fVar1 = lbl_803E6F40;
    iVar2 = *(int *)(iVar2 + 0x40c);
    *(float *)(iVar2 + 0xc) = lbl_803E6F40;
    *(float *)(iVar2 + 0x10) = fVar1;
    *(float *)(iVar2 + 4) = fVar1;
  }
  return 0;
}

#pragma scheduling off
#pragma peephole off
int fn_802002C4(int obj, int p)
{
  extern int *gPlayerInterface;
  extern f32 lbl_803E62A8;
  float fz;
  int b8;

  b8 = *(int *)(obj + 0xb8);
  if (*(char *)(p + 0x27b) != '\0') {
    (**(void (**)(int, int, int))(*gPlayerInterface + 0x14))(obj, p, 1);
    b8 = *(int *)(b8 + 0x40c);
    fz = lbl_803E62A8;
    *(float *)(b8 + 0xc) = lbl_803E62A8;
    *(float *)(b8 + 0x10) = fz;
    *(float *)(b8 + 4) = fz;
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80200380(int obj, int p)
{
  extern int *gPlayerInterface;
  extern f32 lbl_803E62A8;
  int b8;
  float fz;
  s8 flag2;

  b8 = *(int *)(obj + 0xb8);
  if (*(char *)(p + 0x27b) != '\0') {
    b8 = *(int *)(b8 + 0x40c);
    fz = lbl_803E62A8;
    *(float *)(b8 + 0xc) = lbl_803E62A8;
    *(float *)(b8 + 0x10) = fz;
    *(float *)(b8 + 4) = fz;
    (**(void (**)(int, int, int))(*gPlayerInterface + 0x14))(obj, p, 6);
  } else {
    flag2 = *(char *)(p + 0x346);
    if (flag2 != 0) {
      if (*(u8 *)(obj + 0x36) == 0) {
        if (flag2 != 0) {
          return 7;
        }
      }
    }
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80200474
 * EN v1.0 Address: 0x80200474
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x80200964
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80200474(int param_1,int param_2)
{
  if (*(char *)(param_2 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dd738 + 0x4c))
              (param_1,(int)*(short *)(*(int *)(param_1 + 0xb8) + 0x3f0),0xffffffff,0);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802004c8
 * EN v1.0 Address: 0x802004C8
 * EN v1.0 Size: 136b
 * EN v1.1 Address: 0x802009B8
 * EN v1.1 Size: 304b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_802004c8(int param_1,int param_2)
{
  float fVar1;
  int iVar2;
  
  fVar1 = lbl_803E6F40;
  if (*(char *)(param_2 + 0x27b) == '\0') {
    if (((*(char *)(param_2 + 0x346) != '\0') && (*(char *)(param_1 + 0x36) == '\0')) &&
       (*(char *)(param_2 + 0x346) != '\0')) {
      return 7;
    }
  }
  else {
    iVar2 = *(int *)(*(int *)(param_1 + 0xb8) + 0x40c);
    *(float *)(iVar2 + 0xc) = lbl_803E6F40;
    *(float *)(iVar2 + 0x10) = fVar1;
    *(float *)(iVar2 + 4) = fVar1;
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,6);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80200550
 * EN v1.0 Address: 0x80200550
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80200AE8
 * EN v1.1 Size: 672b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80200550(double param_1,ushort *param_2,int param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80200558
 * EN v1.0 Address: 0x80200558
 * EN v1.0 Size: 488b
 * EN v1.1 Address: 0x80200D88
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80200558(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  
  iVar1 = *(int *)(*(int *)(param_9 + 0xb8) + 0x40c);
  *(byte *)(iVar1 + 0x14) = *(byte *)(iVar1 + 0x14) | 2;
  *(byte *)(iVar1 + 0x15) = *(byte *)(iVar1 + 0x15) | 4;
  *(float *)(param_10 + 0x2a0) = lbl_803E6F80;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    param_1 = FUN_800305f8((double)lbl_803E6F40,param_2,param_3,param_4,param_5,param_6,param_7,
                           param_8,param_9,0x11,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 0x1f;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    *(undefined4 *)(iVar1 + 0x18) = *(undefined4 *)(param_10 + 0x2d0);
    *(undefined2 *)(iVar1 + 0x1c) = 0x24;
    *(undefined4 *)(iVar1 + 0x2c) = 0;
    ObjMsg_SendToObject(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(int *)(iVar1 + 0x18),0x11,param_9,0x12,param_13,param_14,param_15,param_16);
    FUN_80006824(param_9,SFXfoot_ice_run_3);
  }
  if (lbl_803E6F84 < *(float *)(param_9 + 0x98)) {
    *(undefined *)(iVar1 + 0x34) = 1;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80200740
 * EN v1.0 Address: 0x80200740
 * EN v1.0 Size: 556b
 * EN v1.1 Address: 0x80200E88
 * EN v1.1 Size: 544b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80200740(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  uint uVar2;
  int iVar3;
  short *psVar4;
  int iVar5;
  double dVar6;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  float local_24;
  float local_20;
  float local_1c;
  
  iVar5 = *(int *)(*(int *)(param_9 + 0xb8) + 0x40c);
  *(byte *)(iVar5 + 0x14) = *(byte *)(iVar5 + 0x14) | 2;
  *(byte *)(iVar5 + 0x15) = *(byte *)(iVar5 + 0x15) & 0xfb;
  fVar1 = lbl_803E6F88;
  *(float *)(param_10 + 0x280) = *(float *)(param_10 + 0x280) / lbl_803E6F88;
  *(float *)(param_10 + 0x284) = *(float *)(param_10 + 0x284) / fVar1;
  *(float *)(param_10 + 0x2a0) = lbl_803E6F8C;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E6F40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0x11,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 0x1f;
  if ((*(float *)(param_9 + 0x98) <= lbl_803E6F84) ||
     (*(float *)(param_9 + 0x10) < *(float *)(*(int *)(param_10 + 0x2d0) + 0x10) - lbl_803E6F90))
  {
    iVar3 = *(int *)(param_10 + 0x2d0);
    local_24 = *(float *)(iVar3 + 0xc) - *(float *)(param_9 + 0xc);
    local_20 = *(float *)(iVar3 + 0x10) - (*(float *)(param_9 + 0x10) + lbl_803E6F94);
    local_1c = *(float *)(iVar3 + 0x14) - *(float *)(param_9 + 0x14);
    dVar6 = FUN_80293900((double)(local_1c * local_1c + local_24 * local_24 + local_20 * local_20));
    if (dVar6 < (double)lbl_803E6F50) {
      local_40 = *(undefined4 *)(param_10 + 0x2d0);
      psVar4 = *(short **)(iVar5 + 0x24);
      local_48 = 0xe;
      local_44 = 1;
      uVar2 = FUN_80006ab8(psVar4);
      if (uVar2 == 0) {
        FUN_80006ac4(psVar4,(uint)&local_48);
      }
      *(undefined *)(iVar5 + 0x34) = 1;
    }
  }
  else {
    psVar4 = *(short **)(iVar5 + 0x24);
    local_30 = 9;
    local_2c = 0;
    local_28 = 0x24;
    uVar2 = FUN_80006ab8(psVar4);
    if (uVar2 == 0) {
      FUN_80006ac4(psVar4,(uint)&local_30);
    }
    *(undefined *)(iVar5 + 0x34) = 1;
    local_34 = *(undefined4 *)(param_10 + 0x2d0);
    psVar4 = *(short **)(iVar5 + 0x24);
    local_3c = 7;
    local_38 = 1;
    uVar2 = FUN_80006ab8(psVar4);
    if (uVar2 == 0) {
      FUN_80006ac4(psVar4,(uint)&local_3c);
    }
    *(undefined *)(iVar5 + 0x34) = 1;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020096c
 * EN v1.0 Address: 0x8020096C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802010A8
 * EN v1.1 Size: 980b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020096c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80200970
 * EN v1.0 Address: 0x80200970
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020147C
 * EN v1.1 Size: 1300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80200970(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80200974
 * EN v1.0 Address: 0x80200974
 * EN v1.0 Size: 808b
 * EN v1.1 Address: 0x80201990
 * EN v1.1 Size: 660b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80200974(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  float fVar1;
  ushort *puVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined4 uVar6;
  undefined4 uVar7;
  short *psVar8;
  int iVar9;
  double dVar10;
  undefined8 uVar11;
  undefined4 local_58;
  undefined4 local_54;
  int local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  
  uVar11 = FUN_80286840();
  fVar1 = lbl_803E6F40;
  puVar2 = (ushort *)((ulonglong)uVar11 >> 0x20);
  iVar5 = (int)uVar11;
  iVar9 = *(int *)(*(int *)(puVar2 + 0x5c) + 0x40c);
  uVar7 = *(undefined4 *)(iVar9 + 0x30);
  uVar6 = *(undefined4 *)(iVar9 + 0x2c);
  *(float *)(iVar5 + 0x280) = lbl_803E6F40;
  *(float *)(iVar5 + 0x284) = fVar1;
  *(byte *)(iVar9 + 0x14) = *(byte *)(iVar9 + 0x14) | 2;
  if ((*(int *)(iVar9 + 0x18) == 0) && (*(short *)(iVar9 + 0x1c) != -1)) {
    local_38 = *(undefined4 *)(iVar9 + 0x30);
    local_3c = *(undefined4 *)(iVar9 + 0x2c);
    psVar8 = *(short **)(iVar9 + 0x24);
    local_40 = *(undefined4 *)(iVar9 + 0x28);
    uVar3 = FUN_80006ab8(psVar8);
    if (uVar3 == 0) {
      FUN_80006ac4(psVar8,(uint)&local_40);
    }
    psVar8 = *(short **)(iVar9 + 0x24);
    local_4c = 8;
    local_48 = uVar6;
    local_44 = uVar7;
    uVar3 = FUN_80006ab8(psVar8);
    if (uVar3 == 0) {
      FUN_80006ac4(psVar8,(uint)&local_4c);
    }
    *(undefined *)(iVar9 + 0x34) = 1;
    local_50 = (int)*(short *)(iVar9 + 0x1c);
    psVar8 = *(short **)(iVar9 + 0x24);
    local_58 = 9;
    local_54 = 0;
    uVar3 = FUN_80006ab8(psVar8);
    if (uVar3 == 0) {
      FUN_80006ac4(psVar8,(uint)&local_58);
    }
    *(undefined *)(iVar9 + 0x34) = 1;
  }
  else {
    *(byte *)(iVar9 + 0x15) = *(byte *)(iVar9 + 0x15) | 4;
    if ((*(int *)(iVar9 + 0x18) != 0) && ((*(uint *)(iVar5 + 0x314) & 0x200) != 0)) {
      iVar4 = *(int *)(iVar5 + 0x2d0);
      local_34 = *(float *)(iVar4 + 0xc) - *(float *)(puVar2 + 6);
      local_30 = *(float *)(iVar4 + 0x10) - *(float *)(puVar2 + 8);
      local_2c = *(float *)(iVar4 + 0x14) - *(float *)(puVar2 + 10);
      dVar10 = FUN_80293900((double)(local_34 * local_34 + local_2c * local_2c));
      local_30 = local_30 * lbl_803E6FA8;
      param_2 = (double)local_30;
      dVar10 = (double)(float)(dVar10 / (double)lbl_803E6FAC);
      dVar10 = (double)(float)(-(double)(float)(dVar10 * (double)(float)((double)lbl_803E6FB0 *
                                                                        dVar10) - param_2) / dVar10)
      ;
      local_24 = (float)(dVar10 * (double)lbl_803E6FB4);
      local_28 = lbl_803E6F40;
      local_20 = lbl_803E6FB8;
      in_r6 = 0x11;
      ObjMsg_SendToObject(dVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   *(int *)(iVar9 + 0x18),0x11,(uint)puVar2,0x11,in_r7,in_r8,in_r9,in_r10);
      (**(code **)(**(int **)(*(int *)(iVar9 + 0x18) + 0x68) + 0x24))
                (*(int *)(iVar9 + 0x18),&local_28);
      *(undefined4 *)(iVar9 + 0x18) = 0;
      *(undefined2 *)(iVar9 + 0x1c) = 0xffff;
    }
    iVar4 = Obj_GetYawDeltaToObject(puVar2,*(int *)(iVar5 + 0x2d0),(float *)0x0);
    *puVar2 = *puVar2 + (short)iVar4;
    *(undefined *)(iVar5 + 0x34d) = 0x11;
    if (*(char *)(iVar5 + 0x27a) != '\0') {
      FUN_800305f8((double)lbl_803E6F40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   puVar2,0x12,0,in_r6,in_r7,in_r8,in_r9,in_r10);
      *(undefined *)(iVar5 + 0x346) = 0;
    }
    if (*(char *)(iVar5 + 0x346) != '\0') {
      *(undefined *)(iVar9 + 0x34) = 1;
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80200c9c
 * EN v1.0 Address: 0x80200C9C
 * EN v1.0 Size: 680b
 * EN v1.1 Address: 0x80201C24
 * EN v1.1 Size: 440b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80200c9c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  short sVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  short *psVar7;
  undefined4 uVar8;
  int iVar9;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  undefined8 uVar10;
  undefined4 local_38;
  undefined4 local_34;
  int local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  
  uVar10 = FUN_8028683c();
  uVar3 = (uint)((ulonglong)uVar10 >> 0x20);
  iVar6 = (int)uVar10;
  iVar9 = *(int *)(*(int *)(uVar3 + 0xb8) + 0x40c);
  uVar8 = *(undefined4 *)(iVar9 + 0x30);
  *(byte *)(iVar9 + 0x14) = *(byte *)(iVar9 + 0x14) | 2;
  fVar2 = lbl_803E6F40;
  *(float *)(iVar6 + 0x280) = lbl_803E6F40;
  *(float *)(iVar6 + 0x284) = fVar2;
  uVar10 = extraout_f1;
  if ((*(int *)(iVar6 + 0x2d0) == 0) ||
     (iVar4 = (**(code **)(**(int **)(*(int *)(iVar6 + 0x2d0) + 0x68) + 0x20))(),
     uVar10 = extraout_f1_00, iVar4 == 0)) {
    *(undefined *)(iVar9 + 0x34) = 1;
  }
  if ((*(int *)(iVar9 + 0x18) == 0) && (sVar1 = *(short *)(iVar9 + 0x1c), sVar1 != -1)) {
    local_24 = *(undefined4 *)(iVar9 + 0x30);
    local_28 = *(undefined4 *)(iVar9 + 0x2c);
    psVar7 = *(short **)(iVar9 + 0x24);
    local_2c = *(undefined4 *)(iVar9 + 0x28);
    uVar5 = FUN_80006ab8(psVar7);
    if (uVar5 == 0) {
      uVar10 = FUN_80006ac4(psVar7,(uint)&local_2c);
    }
    psVar7 = *(short **)(iVar9 + 0x24);
    local_38 = 7;
    local_34 = 0;
    local_30 = (int)sVar1;
    uVar5 = FUN_80006ab8(psVar7);
    if (uVar5 == 0) {
      uVar10 = FUN_80006ac4(psVar7,(uint)&local_38);
    }
    *(undefined *)(iVar9 + 0x34) = 1;
    *(undefined2 *)(iVar9 + 0x1c) = 0xffff;
  }
  if ((*(uint *)(iVar6 + 0x314) & 0x200) != 0) {
    *(undefined4 *)(iVar9 + 0x18) = *(undefined4 *)(iVar6 + 0x2d0);
    *(short *)(iVar9 + 0x1c) = (short)uVar8;
    *(undefined4 *)(iVar9 + 0x2c) = 0;
    in_r6 = 0x12;
    ObjMsg_SendToObject(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(int *)(iVar9 + 0x18),0x11,uVar3,0x12,in_r7,in_r8,in_r9,in_r10);
    FUN_80006824(uVar3,SFXfoot_ice_run_3);
  }
  *(undefined *)(iVar6 + 0x34d) = 0x12;
  if (*(char *)(iVar6 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E6F40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 uVar3,0x10,0,in_r6,in_r7,in_r8,in_r9,in_r10);
    *(undefined *)(iVar6 + 0x346) = 0;
  }
  if (*(char *)(iVar6 + 0x346) != '\0') {
    *(undefined *)(iVar9 + 0x34) = 1;
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80200f44
 * EN v1.0 Address: 0x80200F44
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80201DDC
 * EN v1.1 Size: 1076b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80200f44(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80200f48
 * EN v1.0 Address: 0x80200F48
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80202210
 * EN v1.1 Size: 1240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80200f48(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80200f4c
 * EN v1.0 Address: 0x80200F4C
 * EN v1.0 Size: 788b
 * EN v1.1 Address: 0x802026E8
 * EN v1.1 Size: 484b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80200f4c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  float fVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar5;
  int iVar6;
  int iVar7;
  double dVar8;
  undefined8 uVar9;
  undefined auStack_28 [40];
  
  uVar9 = FUN_80286840();
  uVar2 = (uint)((ulonglong)uVar9 >> 0x20);
  iVar4 = (int)uVar9;
  iVar7 = *(int *)(uVar2 + 0xb8);
  iVar6 = *(int *)(uVar2 + 0x4c);
  iVar5 = *(int *)(iVar7 + 0x40c);
  *(undefined *)(iVar4 + 0x34d) = 0x11;
  fVar1 = lbl_803E6F40;
  if (*(char *)(iVar4 + 0x27a) != '\0') {
    *(float *)(iVar4 + 0x284) = lbl_803E6F40;
    *(float *)(iVar4 + 0x280) = fVar1;
    *(undefined4 *)(iVar4 + 0x2d0) = 0;
    *(undefined *)(iVar4 + 0x25f) = 1;
    *(undefined *)(iVar4 + 0x349) = 0;
    *(byte *)(uVar2 + 0xaf) = *(byte *)(uVar2 + 0xaf) | 8;
    ObjHits_DisableObject(uVar2);
    uVar9 = ObjGroup_RemoveObject(uVar2,3);
    if (*(int *)(iVar5 + 0x18) != 0) {
      in_r6 = 0x10;
      ObjMsg_SendToObject(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   *(int *)(iVar5 + 0x18),0x11,uVar2,0x10,in_r7,in_r8,in_r9,in_r10);
      *(undefined2 *)(iVar5 + 0x1c) = 0xffff;
      *(undefined4 *)(iVar5 + 0x18) = 0;
    }
  }
  if (*(char *)(iVar4 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E6F40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 uVar2,1,0,in_r6,in_r7,in_r8,in_r9,in_r10);
    *(undefined *)(iVar4 + 0x346) = 0;
  }
  *(float *)(iVar4 + 0x2a0) = lbl_803E6FCC;
  dVar8 = (double)*(float *)(uVar2 + 0x98);
  if ((double)lbl_803E6FD0 < dVar8) {
    FUN_80017688((int)*(short *)(iVar6 + 0x18));
    if (*(int *)(iVar6 + 0x14) == -1) {
      FUN_80017ac8(dVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar2);
      goto LAB_802028b4;
    }
    while (uVar3 = FUN_80006ab0(*(short **)(iVar5 + 0x24)), uVar3 == 0) {
      FUN_80006ac0(*(short **)(iVar5 + 0x24),(uint)auStack_28);
    }
    if (*(short *)(iVar6 + 0x2c) == 0) {
      (**(code **)(*DAT_803dd72c + 100))((double)lbl_803E6FD4,*(undefined4 *)(iVar6 + 0x14));
    }
    *(byte *)(iVar7 + 0x404) = *(byte *)(iVar7 + 0x404) | *(byte *)(iVar6 + 0x2b);
  }
  (**(code **)(*DAT_803dd70c + 0x34))(uVar2,iVar4,0,2,&DAT_8032a274);
  (**(code **)(*DAT_803dd70c + 0x34))(uVar2,iVar4,7,0,&DAT_8032a280);
LAB_802028b4:
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80201260
 * EN v1.0 Address: 0x80201260
 * EN v1.0 Size: 616b
 * EN v1.1 Address: 0x802028CC
 * EN v1.1 Size: 404b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80201260(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  uint uVar2;
  short *psVar3;
  int iVar4;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  
  iVar4 = *(int *)(*(int *)(param_9 + 0xb8) + 0x40c);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    param_1 = FUN_800305f8((double)lbl_803E6F40,param_2,param_3,param_4,param_5,param_6,param_7,
                           param_8,param_9,0,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  if (*(char *)(param_10 + 0x27a) != '\0') {
    *(undefined4 *)(param_10 + 0x2d0) = 0;
    if (*(int *)(iVar4 + 0x18) != 0) {
      ObjMsg_SendToObject(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   *(int *)(iVar4 + 0x18),0x11,param_9,0x10,param_13,param_14,param_15,param_16);
      *(undefined4 *)(iVar4 + 0x18) = 0;
    }
    iVar1 = FUN_80017a98();
    iVar1 = (**(code **)(**(int **)(*(int *)(iVar1 + 200) + 0x68) + 0x44))();
    if (iVar1 == 0) {
      uVar2 = randomGetRange(0,2);
      FUN_80006824(param_9,(ushort)*(undefined4 *)(&DAT_8032a290 + uVar2 * 4));
    }
    else {
      uVar2 = randomGetRange(3,4);
      FUN_80006824(param_9,(ushort)*(undefined4 *)(&DAT_8032a290 + uVar2 * 4));
    }
    local_20 = *(undefined4 *)(iVar4 + 0x30);
    local_24 = *(undefined4 *)(iVar4 + 0x2c);
    psVar3 = *(short **)(iVar4 + 0x24);
    local_28 = *(undefined4 *)(iVar4 + 0x28);
    uVar2 = FUN_80006ab8(psVar3);
    if (uVar2 == 0) {
      FUN_80006ac4(psVar3,(uint)&local_28);
    }
    *(undefined4 *)(iVar4 + 0x3c) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 0x10;
  *(float *)(param_10 + 0x2a0) = lbl_803E6FD8;
  *(float *)(param_10 + 0x280) = lbl_803E6F40;
  if (*(char *)(param_10 + 0x346) != '\0') {
    *(undefined *)(iVar4 + 0x34) = 1;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802014c8
 * EN v1.0 Address: 0x802014C8
 * EN v1.0 Size: 400b
 * EN v1.1 Address: 0x80202A60
 * EN v1.1 Size: 252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_802014c8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  undefined4 uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    ObjHits_EnableObject(param_9);
  }
  uVar1 = 0xffffffff;
  ObjHits_SetHitVolumeSlot(param_9,10,1,-1);
  *(float *)(param_10 + 0x2a0) = lbl_803E6F8C;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E6F40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,10,0,uVar1,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 1;
  iVar2 = *(int *)(iVar2 + 0x40c);
  *(byte *)(iVar2 + 0x14) = *(byte *)(iVar2 + 0x14) | 2;
  if ((*(uint *)(param_10 + 0x314) & 1) != 0) {
    *(uint *)(param_10 + 0x314) = *(uint *)(param_10 + 0x314) & ~1;
    *(byte *)(iVar2 + 0x14) = *(byte *)(iVar2 + 0x14) | 1;
  }
  if (*(char *)(param_10 + 0x346) != '\0') {
    *(undefined *)(iVar2 + 0x34) = 1;
  }
  return 0;
}

#pragma scheduling off
#pragma peephole off
int fn_802015EC(int obj, int p)
{
  extern void ObjAnim_SetCurrentMove(int obj, int n, f32 v, int m);
  extern int Stack_IsFull(int sp);
  extern void Stack_Push(int sp, int *args);
  extern f32 lbl_803E62A8;
  int sub_40c;
  int sub_40c_30;
  int frame[3];
  int frame2[3];
  f32 resetValue;

  sub_40c = *(int *)(*(int *)(obj + 0xb8) + 0x40c);
  sub_40c_30 = *(int *)(sub_40c + 0x30);
  *(u8 *)(sub_40c + 0x14) |= 0x2;
  resetValue = lbl_803E62A8;
  *(f32 *)(p + 0x280) = resetValue;
  *(f32 *)(p + 0x284) = resetValue;
  {
    void *p2d0 = *(void **)(p + 0x2d0);
    if (p2d0 == NULL || (**(int (**)(void *))(*(int *)(*(int *)((char *)p2d0 + 0x68)) + 0x20))(p2d0) == 0) {
      *(u8 *)(sub_40c + 0x34) = 1;
    }
  }
  if (*(void **)(sub_40c + 0x18) == NULL) {
    s16 r26 = *(s16 *)(sub_40c + 0x1c);
    if (r26 != -1) {
      int sp_handle;
      sp_handle = *(int *)(sub_40c + 0x24);
      frame[0] = *(int *)(sub_40c + 0x28);
      frame[1] = *(int *)(sub_40c + 0x2c);
      frame[2] = *(int *)(sub_40c + 0x30);
      if (Stack_IsFull(sp_handle) == 0) Stack_Push(sp_handle, frame);
      sp_handle = *(int *)(sub_40c + 0x24);
      frame2[0] = 7;
      frame2[1] = 0;
      frame2[2] = r26;
      if (Stack_IsFull(sp_handle) == 0) Stack_Push(sp_handle, frame2);
      *(u8 *)(sub_40c + 0x34) = 1;
      *(s16 *)(sub_40c + 0x1c) = -1;
    }
  }
  if ((s32)(*(u32 *)(p + 0x314) & 0x200) != 0) {
    *(int *)(sub_40c + 0x18) = *(int *)(p + 0x2d0);
    *(s16 *)(sub_40c + 0x1c) = (s16)sub_40c_30;
    *(int *)(sub_40c + 0x2c) = 0;
    ObjMsg_SendToObject(*(int *)(sub_40c + 0x18), 17, obj, 18);
    Sfx_PlayFromObject(obj, SFXfoot_ice_run_3);
  }
  *(s8 *)(p + 0x34d) = 18;
  if (*(char *)(p + 0x27a) != '\0') {
    ObjAnim_SetCurrentMove(obj, 16, lbl_803E62A8, 0);
    *(s8 *)(p + 0x346) = 0;
  }
  if (*(s8 *)(p + 0x346) != 0) {
    *(u8 *)(sub_40c + 0x34) = 1;
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80201658
 * EN v1.0 Address: 0x80201658
 * EN v1.0 Size: 328b
 * EN v1.1 Address: 0x80202B5C
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80201658(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  undefined4 uVar1;
  
  if (*(char *)(param_10 + 0x27a) != '\0') {
    ObjHits_EnableObject(param_9);
  }
  uVar1 = 0xffffffff;
  ObjHits_SetHitVolumeSlot(param_9,10,1,-1);
  *(float *)(param_10 + 0x2a0) = lbl_803E6F8C;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E6F40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,5,0,uVar1,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 1;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802017a0
 * EN v1.0 Address: 0x802017A0
 * EN v1.0 Size: 568b
 * EN v1.1 Address: 0x80202BF8
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_802017a0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  iVar4 = *(int *)(iVar3 + 0x40c);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    ObjHits_EnableObject(param_9);
  }
  uVar2 = 0xffffffff;
  ObjHits_SetHitVolumeSlot(param_9,10,1,-1);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    uVar1 = randomGetRange(0,1);
    if (uVar1 == 0) {
      if (*(char *)(param_10 + 0x27a) != '\0') {
        FUN_800305f8((double)lbl_803E6F40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,7,0,uVar2,param_13,param_14,param_15,param_16);
        *(undefined *)(param_10 + 0x346) = 0;
      }
    }
    else if (*(char *)(param_10 + 0x27a) != '\0') {
      FUN_800305f8((double)lbl_803E6F40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,6,0,uVar2,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    *(undefined *)(param_10 + 0x34d) = 1;
    *(float *)(param_10 + 0x2a0) =
         lbl_803E6FDC +
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar3 + 0x406)) - DOUBLE_803e6f78) /
         lbl_803E6FE0;
  }
  *(float *)(param_10 + 0x280) = lbl_803E6F40;
  if (*(char *)(param_10 + 0x346) != '\0') {
    *(undefined *)(iVar4 + 0x34) = 1;
  }
  *(byte *)(iVar4 + 0x14) = *(byte *)(iVar4 + 0x14) | 2;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802019d8
 * EN v1.0 Address: 0x802019D8
 * EN v1.0 Size: 708b
 * EN v1.1 Address: 0x80202D58
 * EN v1.1 Size: 416b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802019d8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  uint uVar1;
  int iVar2;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined8 uVar6;
  
  uVar6 = FUN_80286840();
  uVar1 = (uint)((ulonglong)uVar6 >> 0x20);
  iVar2 = (int)uVar6;
  iVar5 = *(int *)(uVar1 + 0xb8);
  iVar3 = *(int *)(uVar1 + 0x4c);
  iVar4 = *(int *)(iVar5 + 0x40c);
  if (*(char *)(iVar2 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E6F40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 uVar1,0xe,0,in_r6,in_r7,in_r8,in_r9,in_r10);
    *(undefined *)(iVar2 + 0x346) = 0;
  }
  *(byte *)(uVar1 + 0xaf) = *(byte *)(uVar1 + 0xaf) | 8;
  if (lbl_803E6FE4 < *(float *)(uVar1 + 0x98)) {
    *(byte *)(iVar4 + 0x14) = *(byte *)(iVar4 + 0x14) | 2;
    ObjHits_DisableObject(uVar1);
  }
  if (*(char *)(iVar2 + 0x27a) != '\0') {
    *(float *)(iVar2 + 0x2a0) = lbl_803E6F8C;
    *(float *)(iVar2 + 0x280) = lbl_803E6F40;
  }
  if (*(char *)(iVar2 + 0x346) != '\0') {
    FUN_80006824(uVar1,SFXfoot_ice_run_2);
    *(float *)(iVar4 + 4) = lbl_803E6F60;
    uVar6 = FUN_800305f8((double)lbl_803E6F40,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,uVar1,8,0,in_r6,in_r7,in_r8,in_r9,in_r10);
    *(undefined4 *)(iVar2 + 0x2d0) = 0;
    *(undefined *)(iVar2 + 0x25f) = 0;
    *(undefined *)(iVar2 + 0x349) = 0;
    *(undefined2 *)(iVar5 + 0x402) = 0;
    *(byte *)(iVar5 + 0x404) = *(byte *)(iVar5 + 0x404) | *(byte *)(iVar3 + 0x2b);
    if (*(int *)(iVar4 + 0x18) != 0) {
      ObjMsg_SendToObject(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   *(int *)(iVar4 + 0x18),0x11,uVar1,0x13,in_r7,in_r8,in_r9,in_r10);
      *(undefined4 *)(iVar4 + 0x18) = 0;
      *(undefined2 *)(iVar4 + 0x1c) = 0xffff;
    }
    if ((*(byte *)(iVar4 + 0x15) & 2) == 0) {
      *(byte *)(uVar1 + 0xaf) = *(byte *)(uVar1 + 0xaf) | 8;
    }
    *(undefined *)(iVar4 + 0x34) = 1;
  }
  (**(code **)(*DAT_803dd70c + 0x34))(uVar1,iVar2,7,0,&DAT_8032a280);
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80201c9c
 * EN v1.0 Address: 0x80201C9C
 * EN v1.0 Size: 344b
 * EN v1.1 Address: 0x80202EF8
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80201c9c(int param_1,int param_2)
{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = *(int *)(iVar2 + 0x40c);
  if (*(char *)(param_2 + 0x27a) == '\0') {
    ObjHits_SetHitVolumeSlot(param_1,10,1,-1);
  }
  else {
    *(undefined *)(param_2 + 0x25f) = 1;
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    *(undefined *)(param_1 + 0x36) = 0xff;
    *(undefined *)(param_2 + 0x34d) = 1;
    *(float *)(param_2 + 0x2a0) =
         lbl_803E6FE8 +
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x406)) - DOUBLE_803e6f78) /
         lbl_803E6FEC;
    ObjHits_EnableObject(param_1);
    *(undefined4 *)(iVar1 + 0x18) = 0;
    *(undefined2 *)(iVar1 + 0x1c) = 0xffff;
  }
  if (*(char *)(param_2 + 0x346) != '\0') {
    *(undefined2 *)(iVar2 + 0x402) = 1;
    *(undefined *)(iVar1 + 0x34) = 1;
  }
  if ((*(uint *)(param_2 + 0x314) & 0x200) != 0) {
    *(uint *)(param_2 + 0x314) = *(uint *)(param_2 + 0x314) & 0xfffffdff;
    *(byte *)(iVar1 + 0x14) = *(byte *)(iVar1 + 0x14) | 4;
  }
  if (*(float *)(param_1 + 0x98) < lbl_803E6FF0) {
    *(byte *)(iVar1 + 0x14) = *(byte *)(iVar1 + 0x14) | 2;
  }
  (**(code **)(*DAT_803dd70c + 0x34))(param_1,param_2,7,0,&DAT_8032a280);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80201df4
 * EN v1.0 Address: 0x80201DF4
 * EN v1.0 Size: 528b
 * EN v1.1 Address: 0x80203064
 * EN v1.1 Size: 588b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80201df4(undefined4 param_1,undefined4 param_2,float *param_3,int param_4)
{
  float fVar1;
  short *psVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 *puVar6;
  double dVar7;
  double extraout_f1;
  double dVar8;
  double in_f28;
  double dVar9;
  double in_f29;
  double in_f30;
  double dVar10;
  double in_f31;
  double dVar11;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar12;
  float local_78;
  float local_74;
  float local_70;
  float local_6c;
  undefined4 local_68;
  uint uStack_64;
  undefined4 local_60;
  uint uStack_5c;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  uVar12 = FUN_8028683c();
  psVar2 = (short *)((ulonglong)uVar12 >> 0x20);
  puVar6 = (undefined4 *)uVar12;
  iVar5 = *(int *)(psVar2 + 0x5c);
  dVar10 = (double)lbl_803E6F40;
  dVar11 = (double)lbl_803E6FF4;
  dVar9 = extraout_f1;
  dVar7 = dVar10;
  for (iVar4 = 0; iVar4 < param_4; iVar4 = iVar4 + 1) {
    local_78 = (float)dVar11;
    iVar3 = ObjGroup_FindNearestObjectForObject(*puVar6,psVar2,&local_78);
    if (iVar3 != 0) {
      if (local_78 == lbl_803E6F40) goto LAB_80203278;
      fVar1 = lbl_803E6F60 - local_78 / lbl_803E6FF4;
      fVar1 = fVar1 * fVar1;
      fVar1 = fVar1 * fVar1;
      local_6c = lbl_803E6F60 / local_78;
      local_74 = (*(float *)(iVar3 + 0xc) - *(float *)(psVar2 + 6)) * local_6c;
      local_70 = (*(float *)(iVar3 + 0x10) - *(float *)(psVar2 + 8)) * local_6c;
      local_6c = (*(float *)(iVar3 + 0x14) - *(float *)(psVar2 + 10)) * local_6c;
      dVar7 = -(double)(float)(dVar9 * (double)(local_74 * fVar1 * *param_3) - dVar7);
      dVar10 = -(double)(float)(dVar9 * (double)(local_6c * fVar1 * *param_3) - dVar10);
    }
    puVar6 = puVar6 + 1;
    param_3 = param_3 + 1;
  }
  uStack_64 = (int)*psVar2 ^ 0x80000000;
  local_68 = 0x43300000;
  dVar11 = (double)FUN_80293f90();
  uStack_5c = (int)*psVar2 ^ 0x80000000;
  local_60 = 0x43300000;
  dVar8 = (double)FUN_80294964();
  *(float *)(iVar5 + 0x284) =
       *(float *)(iVar5 + 0x284) + (float)(dVar7 * dVar8 - (double)(float)(dVar10 * dVar11));
  *(float *)(iVar5 + 0x280) =
       *(float *)(iVar5 + 0x280) + (float)(-dVar10 * dVar8 - (double)(float)(dVar7 * dVar11));
  dVar11 = (double)*(float *)(iVar5 + 0x280);
  dVar7 = -dVar9;
  dVar10 = dVar7;
  if ((dVar7 <= dVar11) && (dVar10 = dVar11, dVar9 < dVar11)) {
    dVar10 = dVar9;
  }
  *(float *)(iVar5 + 0x280) = (float)dVar10;
  dVar10 = (double)*(float *)(iVar5 + 0x284);
  if ((dVar7 <= dVar10) && (dVar7 = dVar10, dVar9 < dVar10)) {
    dVar7 = dVar9;
  }
  *(float *)(iVar5 + 0x284) = (float)dVar7;
LAB_80203278:
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80202004
 * EN v1.0 Address: 0x80202004
 * EN v1.0 Size: 300b
 * EN v1.1 Address: 0x802032B0
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80202004(double param_1,double param_2,undefined8 param_3,double param_4,ushort *param_5,
            int param_6)
{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  float local_48 [5];
  
  iVar3 = *(int *)(param_5 + 0x5c);
  iVar1 = Obj_GetYawDeltaToObject(param_5,param_6,local_48);
  if ((double)lbl_803E6F40 == param_4) {
    uVar2 = 0;
  }
  else {
    dVar5 = (double)(float)((double)(float)((double)local_48[0] - param_1) / param_4);
    dVar4 = dVar5;
    if (dVar5 < (double)lbl_803E6F40) {
      dVar4 = -dVar5;
    }
    if ((double)lbl_803E7008 <= dVar4) {
      if (dVar5 < (double)lbl_803E6F40) {
        param_2 = -param_2;
      }
      *(float *)(iVar3 + 0x280) =
           lbl_803DC074 * lbl_803E6FE4 *
           ((float)(param_2 *
                   (double)(lbl_803E6F60 -
                           (float)((double)CONCAT44(0x43300000,(int)(short)iVar1 ^ 0x80000000) -
                                  DOUBLE_803e7000) / lbl_803E700C)) - *(float *)(iVar3 + 0x280)) +
           *(float *)(iVar3 + 0x280);
      *(float *)(iVar3 + 0x284) = lbl_803E6F40;
      uVar2 = 0;
    }
    else {
      uVar2 = 1;
    }
  }
  return uVar2;
}

#pragma scheduling off
#pragma peephole off
int fn_802020B0(int obj, int p2)
{
  extern void ObjHits_DisableObject(int);
  extern void ObjGroup_RemoveObject(int, int);
  extern void ObjAnim_SetCurrentMove(int, int, f32, int);
  extern int gameBitIncrement(int);
  extern void Obj_FreeObject(int);
  extern void Stack_Pop(int, int *);
  extern int Stack_IsEmpty(int);
  extern int *gMapEventInterface;
  extern int *gPlayerInterface;
  extern int lbl_80329634[];
  extern int lbl_80329640[];
  extern f32 lbl_803E62A8;
  extern f32 lbl_803E6334;
  extern f32 lbl_803E6338;
  extern f32 lbl_803E633C;

  int sub = *(int *)(obj + 0xb8);
  int data = *(int *)(obj + 0x4c);
  int sub_40c = *(int *)(sub + 0x40c);

  *(s8 *)(p2 + 0x34d) = 0x11;

  if ((s32)(s8)*(u8 *)(p2 + 0x27a) != 0) {
    f32 fz = lbl_803E62A8;
    *(f32 *)(p2 + 0x284) = fz;
    *(f32 *)(p2 + 0x280) = fz;
    *(int *)(p2 + 0x2d0) = 0;
    *(u8 *)(p2 + 0x25f) = 1;
    *(u8 *)(p2 + 0x349) = 0;
    *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 0x8);
    ObjHits_DisableObject(obj);
    ObjGroup_RemoveObject(obj, 3);
    if (*(void **)(sub_40c + 0x18) != NULL) {
      ObjMsg_SendToObject((void *)*(int *)(sub_40c + 0x18), 17, obj, 16);
      *(s16 *)(sub_40c + 0x1c) = -1;
      *(int *)(sub_40c + 0x18) = 0;
    }
  }
  if ((s32)(s8)*(u8 *)(p2 + 0x27a) != 0) {
    ObjAnim_SetCurrentMove(obj, 1, lbl_803E62A8, 0);
    *(u8 *)(p2 + 0x346) = 0;
  }
  *(f32 *)(p2 + 0x2a0) = lbl_803E6334;
  if (*(f32 *)(obj + 0x98) > lbl_803E6338) {
    int local;
    gameBitIncrement(*(s16 *)(data + 0x18));
    if ((*(u32 *)(data + 0x14) + 0x10000) == 0xffff) {
      Obj_FreeObject(obj);
      return 0;
    }
    while (Stack_IsEmpty(*(int *)(sub_40c + 0x24)) == 0) {
      Stack_Pop(*(int *)(sub_40c + 0x24), &local);
    }
    if (*(s16 *)(data + 0x2c) == 0) {
      (**(void (**)(int, f32))((char *)(*gMapEventInterface) + 0x64))(*(int *)(data + 0x14), lbl_803E633C);
    }
    *(u8 *)(sub + 0x404) |= *(u8 *)(data + 0x2b);
  }
  (**(void (**)(int, int, int, int, int *))((char *)(*gPlayerInterface) + 0x34))(obj, p2, 0, 2, lbl_80329634);
  (**(void (**)(int, int, int, int, int *))((char *)(*gPlayerInterface) + 0x34))(obj, p2, 7, 0, lbl_80329640);
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80202130
 * EN v1.0 Address: 0x80202130
 * EN v1.0 Size: 312b
 * EN v1.1 Address: 0x802033DC
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80202130(double param_1,double param_2,undefined8 param_3,double param_4,ushort *param_5,
            int param_6)
{
  int iVar1;
  int iVar2;
  double dVar3;
  float local_58 [7];
  
  iVar2 = *(int *)(param_5 + 0x5c);
  if ((param_5 != (ushort *)0x0) && (param_6 != 0)) {
    iVar1 = Obj_GetYawDeltaToObject(param_5,param_6,local_58);
    if ((double)lbl_803E6F40 != param_4) {
      if ((double)local_58[0] < param_1) {
        dVar3 = (double)(*(float *)(param_5 + 8) - *(float *)(param_6 + 0x10));
        if (dVar3 < (double)lbl_803E6F40) {
          dVar3 = -dVar3;
        }
        if (dVar3 < (double)lbl_803E7010) {
          return 1;
        }
      }
      *(float *)(iVar2 + 0x280) =
           lbl_803DC074 * lbl_803E6FE4 *
           ((float)(param_2 *
                   (double)(lbl_803E6F60 -
                           (float)((double)CONCAT44(0x43300000,(int)(short)iVar1 ^ 0x80000000) -
                                  DOUBLE_803e7000) / lbl_803E700C)) - *(float *)(iVar2 + 0x280)) +
           *(float *)(iVar2 + 0x280);
      *(float *)(iVar2 + 0x284) = lbl_803E6F40;
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80202268
 * EN v1.0 Address: 0x80202268
 * EN v1.0 Size: 428b
 * EN v1.1 Address: 0x80203528
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80202268(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  float fVar1;
  float fVar2;
  uint uVar3;
  undefined2 *puVar4;
  int iVar5;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  double dVar6;
  
  uVar3 = FUN_80017ae8();
  if ((uVar3 & 0xff) != 0) {
    puVar4 = FUN_80017aa4(0x24,0x30a);
    *(undefined4 *)(puVar4 + 4) = *(undefined4 *)(param_9 + 0xc);
    dVar6 = (double)lbl_803E7014;
    *(float *)(puVar4 + 6) = (float)(dVar6 + (double)*(float *)(param_9 + 0x10));
    *(undefined4 *)(puVar4 + 8) = *(undefined4 *)(param_9 + 0x14);
    *(undefined *)(puVar4 + 2) = 1;
    *(undefined *)((int)puVar4 + 5) = 1;
    *(undefined *)(puVar4 + 3) = 0xff;
    *(undefined *)((int)puVar4 + 7) = 0xff;
    iVar5 = FUN_80017ae4(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar4,5,
                         *(undefined *)(param_9 + 0xac),0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    if (iVar5 != 0) {
      fVar1 = *(float *)(param_10 + 0x2c0) / lbl_803E6F4C;
      fVar2 = lbl_803E6F50 * fVar1;
      *(float *)(iVar5 + 0x24) =
           (*(float *)(*(int *)(param_10 + 0x2d0) + 0xc) - *(float *)(param_9 + 0xc)) / fVar2;
      *(float *)(iVar5 + 0x28) =
           ((lbl_803E7018 * fVar1 + *(float *)(*(int *)(param_10 + 0x2d0) + 0x10)) -
           *(float *)(param_9 + 0x10)) / fVar2;
      *(float *)(iVar5 + 0x2c) =
           (*(float *)(*(int *)(param_10 + 0x2d0) + 0x14) - *(float *)(param_9 + 0x14)) / fVar2;
      *(int *)(iVar5 + 0xc4) = param_9;
    }
  }
  return;
}

#pragma scheduling off
#pragma peephole off
int fn_80202294(int obj, int p)
{
  extern void ObjAnim_SetCurrentMove(int obj, int n, f32 v, int m);
  extern void *Obj_GetPlayerObject(void);
  extern int lbl_80329650[];
  extern int Stack_IsFull(int sp);
  extern void Stack_Push(int sp, int *args);
  extern f32 lbl_803E62A8;
  extern f32 lbl_803E6340;
  int sub_40c;
  int frame[3];

  sub_40c = *(int *)(*(int *)(obj + 0xb8) + 0x40c);
  if (*(char *)(p + 0x27a) != '\0') {
    ObjAnim_SetCurrentMove(obj, 0, lbl_803E62A8, 0);
    *(s8 *)(p + 0x346) = 0;
  }
  if (*(char *)(p + 0x27a) != '\0') {
    int r;
    int player_c8;
    *(u32 *)(p + 0x2d0) = 0;
    if (*(void **)(sub_40c + 0x18) != NULL) {
      ObjMsg_SendToObject(*(int *)(sub_40c + 0x18), 17, obj, 16);
      *(int *)(sub_40c + 0x18) = 0;
    }
    player_c8 = *(int *)((char *)Obj_GetPlayerObject() + 0xc8);
    r = (**(int (**)(int))(*(int *)(*(int *)(player_c8 + 0x68)) + 0x44))(player_c8);
    if (r != 0) {
      Sfx_PlayFromObject(obj, (u16)lbl_80329650[randomGetRange(3, 4)]);
    } else {
      Sfx_PlayFromObject(obj, (u16)lbl_80329650[randomGetRange(0, 2)]);
    }
    {
      int frame1;
      int frame2;
      int sp_handle;
      int frame0;
      frame2 = *(int *)(sub_40c + 0x30);
      frame1 = *(int *)(sub_40c + 0x2c);
      sp_handle = *(int *)(sub_40c + 0x24);
      frame0 = *(int *)(sub_40c + 0x28);
      frame[0] = frame0;
      frame[1] = frame1;
      frame[2] = frame2;
      if (Stack_IsFull(sp_handle) == 0) {
        Stack_Push(sp_handle, frame);
      }
    }
    *(int *)(sub_40c + 0x3c) = 0;
  }
  *(s8 *)(p + 0x34d) = 16;
  *(f32 *)(p + 0x2a0) = lbl_803E6340;
  *(f32 *)(p + 0x280) = lbl_803E62A8;
  if (*(s8 *)(p + 0x346) != 0) {
    *(u8 *)(sub_40c + 0x34) = 1;
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80202414
 * EN v1.0 Address: 0x80202414
 * EN v1.0 Size: 696b
 * EN v1.1 Address: 0x80203638
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80202414(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  int iVar1;
  int iVar2;
  
  iVar1 = *(int *)(param_10 + 0x40c);
  if (((*(byte *)(iVar1 + 0x14) & 1) != 0) && (*(int *)(param_10 + 0x2d0) != 0)) {
    FUN_80202268(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10);
  }
  if ((*(byte *)(iVar1 + 0x14) & 2) != 0) {
    (**(code **)(*DAT_803dd708 + 8))(param_9,0x345,0,2,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(param_9,0x345,0,2,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(param_9,0x345,0,2,0xffffffff,0);
  }
  if ((*(byte *)(iVar1 + 0x14) & 4) != 0) {
    iVar2 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x343,0,1,0xffffffff,0);
      iVar2 = iVar2 + 1;
    } while (iVar2 < 10);
  }
  *(undefined *)(iVar1 + 0x14) = 0;
  return;
}

#pragma scheduling off
#pragma peephole off
int fn_80202524(int obj, int p)
{
  extern void ObjHits_EnableObject(int obj);
  extern void ObjHits_SetHitVolumeSlot(int obj, int slot, int a, int b);
  extern void ObjAnim_SetCurrentMove(int obj, int n, f32 v, int m);
  extern f32 lbl_803E62A8;
  extern f32 lbl_803E62F4;

  if (*(char *)(p + 0x27a) != '\0') {
    ObjHits_EnableObject(obj);
  }
  ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
  *(f32 *)(p + 0x2a0) = lbl_803E62F4;
  if (*(char *)(p + 0x27a) != '\0') {
    ObjAnim_SetCurrentMove(obj, 5, lbl_803E62A8, 0);
    *(s8 *)(p + 0x346) = 0;
  }
  *(s8 *)(p + 0x34d) = 1;
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_802026cc
 * EN v1.0 Address: 0x802026CC
 * EN v1.0 Size: 548b
 * EN v1.1 Address: 0x8020377C
 * EN v1.1 Size: 760b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802026cc(undefined4 param_1,undefined4 param_2,int param_3)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  undefined8 uVar7;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 local_20;
  uint uStack_1c;
  
  uVar7 = FUN_8028683c();
  uVar1 = (uint)((ulonglong)uVar7 >> 0x20);
  iVar3 = (int)uVar7;
  iVar5 = *(int *)(iVar3 + 0x40c);
  local_30 = lbl_803E6F48;
  iVar4 = *(int *)(uVar1 + 0x4c);
  uStack_1c = (uint)*(ushort *)(iVar3 + 0x3fe);
  local_20 = 0x43300000;
  iVar2 = (**(code **)(*DAT_803dd738 + 0x48))
                    ((double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e6f78),uVar1
                     ,param_3,0x8000);
  if ((iVar2 == 0) && ((*(byte *)(iVar3 + 0x404) & 0x10) != 0)) {
    iVar2 = ObjGroup_FindNearestObject(0x24,uVar1,&local_30);
  }
  if ((((iVar2 == 0) && ((*(byte *)(iVar3 + 0x404) & 0x10) != 0)) &&
      ((*(byte *)(iVar3 + 0x404) & 2) == 0)) && ((*(byte *)(iVar4 + 0x2b) & 2) != 0)) {
    iVar2 = ObjGroup_FindNearestObject(0x24,uVar1,(float *)0x0);
  }
  if ((iVar2 == 0) || ((*(byte *)(iVar3 + 0x404) & 2) != 0)) {
    iVar2 = FUN_80017a98();
    if (iVar2 == 0) {
      dVar6 = (double)lbl_803E6FEC;
    }
    else {
      local_2c = *(float *)(iVar2 + 0x18) - *(float *)(uVar1 + 0x18);
      local_28 = *(float *)(iVar2 + 0x1c) - *(float *)(uVar1 + 0x1c);
      local_24 = *(float *)(iVar2 + 0x20) - *(float *)(uVar1 + 0x20);
      dVar6 = FUN_80293900((double)(local_24 * local_24 + local_2c * local_2c + local_28 * local_28)
                          );
    }
    if ((*(float *)(iVar5 + 0x10) < *(float *)(iVar5 + 0xc)) && (dVar6 < (double)lbl_803E701C)) {
      FUN_80006824(uVar1,(ushort)DAT_8032a284);
      uStack_1c = randomGetRange(0x32,0xfa);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      *(float *)(iVar5 + 0x10) =
           *(float *)(iVar5 + 0x10) +
           (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e7000);
    }
    *(float *)(iVar5 + 0xc) = *(float *)(iVar5 + 0xc) + lbl_803DC074;
  }
  else {
    (**(code **)(*DAT_803dd738 + 0x28))
              (uVar1,param_3,iVar3 + 0x35c,(int)*(short *)(iVar3 + 0x3f4),0,0,0,8,0xffffffff);
    *(int *)(param_3 + 0x2d0) = iVar2;
    *(undefined *)(param_3 + 0x349) = 0;
    ObjGroup_AddObject(uVar1,3);
    *(undefined2 *)(iVar3 + 0x402) = 1;
  }
  FUN_80286888();
  return;
}

#pragma scheduling off
#pragma peephole off
int fn_80202720(int obj, int p)
{
  extern void ObjAnim_SetCurrentMove(int obj, int n, f32 v, int m);
  extern int *gPlayerInterface;
  extern int lbl_80329640[];
  extern f32 lbl_803E62A8;
  extern f32 lbl_803E62C8;
  extern f32 lbl_803E62F4;
  extern f32 lbl_803E634C;
  int sub;
  int sub_40c;
  int p4c;

  sub = *(int *)(obj + 0xb8);
  p4c = *(int *)(obj + 0x4c);
  sub_40c = *(int *)(sub + 0x40c);
  if (*(char *)(p + 0x27a) != '\0') {
    ObjAnim_SetCurrentMove(obj, 14, lbl_803E62A8, 0);
    *(s8 *)(p + 0x346) = 0;
  }
  *(u8 *)(obj + 0xaf) |= 0x8;
  if (*(f32 *)(obj + 0x98) > lbl_803E634C) {
    *(u8 *)(sub_40c + 0x14) |= 0x2;
    ObjHits_DisableObject(obj);
  }
  if (*(char *)(p + 0x27a) != '\0') {
    *(f32 *)(p + 0x2a0) = lbl_803E62F4;
    *(f32 *)(p + 0x280) = lbl_803E62A8;
  }
  if (*(s8 *)(p + 0x346) != 0) {
    Sfx_PlayFromObject(obj, SFXfoot_ice_run_2);
    *(f32 *)(sub_40c + 4) = lbl_803E62C8;
    ObjAnim_SetCurrentMove(obj, 8, lbl_803E62A8, 0);
    *(u32 *)(p + 0x2d0) = 0;
    *(u8 *)(p + 0x25f) = 0;
    *(u8 *)(p + 0x349) = 0;
    *(s16 *)(sub + 0x402) = 0;
    *(u8 *)(sub + 0x404) |= *(u8 *)(p4c + 0x2b);
    if (*(void **)(sub_40c + 0x18) != NULL) {
      ObjMsg_SendToObject(*(int *)(sub_40c + 0x18), 17, obj, 19);
      *(int *)(sub_40c + 0x18) = 0;
      *(s16 *)(sub_40c + 0x1c) = -1;
    }
    if ((*(u8 *)(sub_40c + 0x15) & 0x2) == 0) {
      *(u8 *)(obj + 0xaf) |= 0x8;
    }
    *(u8 *)(sub_40c + 0x34) = 1;
  }
  (**(int (**)(int, int, int, int, int *))(*gPlayerInterface + 0x34))(obj, p, 7, 0, lbl_80329640);
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_802028f0
 * EN v1.0 Address: 0x802028F0
 * EN v1.0 Size: 252b
 * EN v1.1 Address: 0x80203A74
 * EN v1.1 Size: 136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802028f0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  iVar1 = *(int *)(iVar2 + 0x40c);
  ObjGroup_RemoveObject(param_9,3);
  uVar3 = FUN_80006ac8(*(uint *)(iVar1 + 0x24));
  if (*(int *)(param_9 + 200) != 0) {
    FUN_80017ac8(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(int *)(param_9 + 200));
    *(undefined4 *)(param_9 + 200) = 0;
  }
  (**(code **)(*DAT_803dd738 + 0x40))(param_9,iVar2,3);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_802029ec
 * EN v1.0 Address: 0x802029EC
 * EN v1.0 Size: 328b
 * EN v1.1 Address: 0x80203AFC
 * EN v1.1 Size: 368b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802029ec(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = FUN_80286838();
  iVar2 = *(int *)(iVar1 + 0xb8);
  iVar3 = *(int *)(iVar2 + 0x40c);
  if (*(int *)(iVar3 + 0x18) != 0) {
    *(undefined4 *)(*(int *)(iVar3 + 0x18) + 0xc) = *(undefined4 *)(iVar1 + 0xc);
    *(undefined4 *)(*(int *)(iVar3 + 0x18) + 0x10) = *(undefined4 *)(iVar1 + 0x10);
    *(undefined4 *)(*(int *)(iVar3 + 0x18) + 0x14) = *(undefined4 *)(iVar1 + 0x14);
    *(float *)(*(int *)(iVar3 + 0x18) + 0x10) =
         *(float *)(*(int *)(iVar3 + 0x18) + 0x10) + lbl_803E6F68;
  }
  if (((visible != '\0') && (*(int *)(iVar1 + 0xf4) == 0)) && (*(short *)(iVar2 + 0x402) != 0)) {
    if (*(float *)(iVar2 + 1000) != lbl_803E6F40) {
      FUN_8003b540(200,0,0,(char)(int)*(float *)(iVar2 + 1000));
    }
    FUN_8003b818(iVar1);
    if ((*(ushort *)(iVar2 + 0x400) & 0x60) != 0) {
      FUN_8008111c((double)lbl_803E6F60,(double)*(float *)(iVar2 + 1000),iVar1,3,(int *)0x0);
    }
    iVar2 = *(int *)(iVar3 + 0x18);
    if ((iVar2 != 0) && (*(int *)(iVar2 + 0x50) != 0)) {
      ObjPath_GetPointWorldPosition(iVar1,3,(float *)(iVar2 + 0xc),(undefined4 *)(iVar2 + 0x10),
                   (float *)(iVar2 + 0x14),0);
      FUN_8003b818(*(int *)(iVar3 + 0x18));
    }
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80202b34
 * EN v1.0 Address: 0x80202B34
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x80203C6C
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80202b34(int param_1)
{
  (**(code **)(*DAT_803dd70c + 0xc))(param_1,*(undefined4 *)(param_1 + 0xb8),&DAT_803add54);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80202b70
 * EN v1.0 Address: 0x80202B70
 * EN v1.0 Size: 1992b
 * EN v1.1 Address: 0x80203CA8
 * EN v1.1 Size: 1080b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80202b70(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  short sVar1;
  uint uVar2;
  undefined4 uVar3;
  uint uVar4;
  undefined4 in_r7;
  undefined4 uVar5;
  undefined4 in_r8;
  undefined4 uVar6;
  undefined4 in_r9;
  undefined4 uVar7;
  undefined4 in_r10;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  double extraout_f1;
  double dVar13;
  undefined8 extraout_f1_00;
  undefined8 uVar14;
  uint local_48 [3];
  float local_3c;
  float local_38;
  float local_34;
  
  uVar2 = FUN_80286830();
  iVar12 = *(int *)(uVar2 + 0xb8);
  iVar11 = *(int *)(uVar2 + 0x4c);
  iVar10 = *(int *)(iVar12 + 0x40c);
  *(byte *)(uVar2 + 0xaf) = *(byte *)(uVar2 + 0xaf) | 8;
  if ((*(byte *)(iVar10 + 0x44) >> 4 & 1) != 0) {
    sVar1 = *(short *)(iVar11 + 0x24);
    uVar3 = FUN_80006acc(0x14,0xc);
    *(undefined4 *)(iVar10 + 0x24) = uVar3;
    iVar8 = (int)*(short *)(&DAT_8032a158 + sVar1 * 8);
    iVar9 = iVar8 * 0xc;
    for (; iVar8 != 0; iVar8 = iVar8 + -1) {
      iVar9 = iVar9 + -0xc;
      FUN_80006ac4(*(short **)(iVar10 + 0x24),(uint)((&PTR_DAT_8032a154)[sVar1 * 2] + iVar9));
    }
    *(undefined *)(iVar10 + 0x34) = 1;
    *(byte *)(iVar10 + 0x44) = *(byte *)(iVar10 + 0x44) & 0xef;
  }
  uVar4 = FUN_80017690((int)*(short *)(iVar12 + 0x3f6));
  if (uVar4 != 0) {
    if (*(int *)(uVar2 + 0xf4) == 0) {
      if (*(int *)(uVar2 + 0xf8) == 0) {
        *(undefined4 *)(uVar2 + 0xc) = *(undefined4 *)(iVar11 + 8);
        *(undefined4 *)(uVar2 + 0x10) = *(undefined4 *)(iVar11 + 0xc);
        *(undefined4 *)(uVar2 + 0x14) = *(undefined4 *)(iVar11 + 0x10);
        (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar11 + 0x2e),uVar2,0xffffffff);
        *(undefined4 *)(uVar2 + 0xf8) = 1;
      }
      else {
        iVar10 = (**(code **)(*DAT_803dd738 + 0x30))(uVar2,iVar12,0);
        if (iVar10 == 0) {
          *(undefined2 *)(iVar12 + 0x402) = 0;
        }
        else {
          iVar10 = *(int *)(iVar12 + 0x2d0);
          dVar13 = extraout_f1;
          if (iVar10 != 0) {
            local_3c = *(float *)(iVar10 + 0x18) - *(float *)(uVar2 + 0x18);
            param_4 = (double)local_3c;
            local_38 = *(float *)(iVar10 + 0x1c) - *(float *)(uVar2 + 0x1c);
            param_3 = (double)local_38;
            local_34 = *(float *)(iVar10 + 0x20) - *(float *)(uVar2 + 0x20);
            param_2 = (double)(local_34 * local_34);
            dVar13 = FUN_80293900((double)(float)(param_2 +
                                                 (double)((float)(param_4 * param_4) +
                                                         (float)(param_3 * param_3))));
            *(float *)(iVar12 + 0x2c0) = (float)dVar13;
          }
          local_48[0] = 0;
          local_48[1] = 0;
          iVar10 = *(int *)(*(int *)(uVar2 + 0xb8) + 0x40c);
          while (iVar11 = ObjMsg_Pop(uVar2,local_48,local_48 + 2,local_48 + 1), iVar11 != 0) {
            if ((local_48[0] == 0x11) && (*(short *)(iVar10 + 0x1c) != -1)) {
              uVar3 = 0x14;
              ObjMsg_SendToObject(dVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           *(int *)(iVar10 + 0x18),0x11,uVar2,0x14,in_r7,in_r8,in_r9,in_r10);
              *(undefined4 *)(iVar10 + 0x18) = 0;
              *(undefined2 *)(iVar10 + 0x1c) = 0xffff;
              dVar13 = (double)FUN_800305f8((double)lbl_803E6F40,param_2,param_3,param_4,param_5,
                                            param_6,param_7,param_8,uVar2,0xf,0,uVar3,in_r7,in_r8,
                                            in_r9,in_r10);
            }
          }
          iVar10 = (**(code **)(*DAT_803dd738 + 0x50))
                             (uVar2,iVar12,iVar12 + 0x35c,(int)*(short *)(iVar12 + 0x3f4),
                              &DAT_8032a2a4,&DAT_8032a31c,1,&DAT_803add20);
          uVar14 = extraout_f1_00;
          if (iVar10 != 0) {
            DAT_803add2c = *(undefined4 *)(uVar2 + 0xc);
            DAT_803add30 = *(undefined4 *)(uVar2 + 0x10);
            DAT_803add34 = *(undefined4 *)(uVar2 + 0x14);
            uVar14 = FUN_80081120(uVar2,&DAT_803add20,1,(int *)0x0);
          }
          if (*(short *)(iVar12 + 0x402) == 0) {
            FUN_802026cc(uVar2,iVar12,iVar12);
          }
          else {
            iVar10 = *(int *)(iVar12 + 0x40c);
            FUN_80202414(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar2,iVar12
                        );
            (**(code **)(*DAT_803dd738 + 0x2c))((double)lbl_803E7020,uVar2,iVar12,0xffffffff);
            if ((*(byte *)(iVar10 + 0x15) & 4) == 0) {
              (**(code **)(*DAT_803dd70c + 0x30))((double)lbl_803DC074,uVar2,iVar12,4);
            }
            *(undefined4 *)(iVar12 + 0x3e0) = *(undefined4 *)(uVar2 + 0xc0);
            *(undefined4 *)(uVar2 + 0xc0) = 0;
            (**(code **)(*DAT_803dd70c + 8))
                      ((double)lbl_803DC074,(double)lbl_803DC074,uVar2,iVar12,&DAT_803add54,
                       &DAT_803add38);
            *(undefined4 *)(uVar2 + 0xc0) = *(undefined4 *)(iVar12 + 0x3e0);
          }
        }
      }
    }
    else if (((*(byte *)(iVar12 + 0x404) & 4) == 0) &&
            (iVar10 = (**(code **)(*DAT_803dd72c + 0x68))(*(undefined4 *)(iVar11 + 0x14)),
            iVar10 != 0)) {
      uVar3 = 0x10;
      uVar5 = 7;
      uVar6 = 0x10a;
      uVar7 = 0x26;
      iVar10 = *DAT_803dd738;
      (**(code **)(iVar10 + 0x58))((double)lbl_803E6F94,uVar2,iVar11,iVar12);
      ObjGroup_AddObject(uVar2,3);
      *(undefined2 *)(iVar12 + 0x402) = 0;
      FUN_800305f8((double)lbl_803E6F40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   uVar2,8,0x10,uVar3,uVar5,uVar6,uVar7,iVar10);
      *(undefined *)(iVar12 + 0x346) = 0;
      *(undefined *)(uVar2 + 0x36) = 0xff;
      *(byte *)(uVar2 + 0xaf) = *(byte *)(uVar2 + 0xaf) | 8;
    }
  }
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80203338
 * EN v1.0 Address: 0x80203338
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802040E0
 * EN v1.1 Size: 432b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80203338(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10,int param_11)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020333c
 * EN v1.0 Address: 0x8020333C
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x80204290
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020333c(void)
{
  FUN_8020335c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8020335c
 * EN v1.0 Address: 0x8020335C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802042B0
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020335c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80203360
 * EN v1.0 Address: 0x80203360
 * EN v1.0 Size: 584b
 * EN v1.1 Address: 0x802043D8
 * EN v1.1 Size: 396b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80203360(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  bool bVar1;
  uint uVar2;
  undefined2 *puVar3;
  uint uVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  undefined8 extraout_f1;
  undefined8 uVar8;
  int local_28 [10];
  
  uVar2 = FUN_8028683c();
  iVar7 = *(int *)(uVar2 + 0x4c);
  uVar8 = extraout_f1;
  for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar6 = iVar6 + 1) {
    if ((((*(char *)(param_11 + iVar6 + 0x81) == '\x01') &&
         (uVar4 = FUN_80017690((int)*(char *)(iVar7 + 0x19) + 0xa29), uVar4 == 0)) &&
        (uVar4 = FUN_80017ae8(), (uVar4 & 0xff) != 0)) &&
       (uVar4 = FUN_8005b54c(0x4658a,(int *)0x0,(int *)0x0,(int *)0x0,(uint *)0x0), uVar4 != 0)) {
      puVar3 = FUN_80017aa4(0x38,0x539);
      uVar8 = FUN_80003494((uint)puVar3,uVar4,0x38);
      *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(uVar2 + 0xc);
      *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(uVar2 + 0x10);
      *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(uVar2 + 0x14);
      *(undefined4 *)(puVar3 + 10) = 0xffffffff;
      puVar3[0xd] = 0x95;
      FUN_80017a5c(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar2,puVar3);
    }
  }
  uVar4 = FUN_80017690((int)*(short *)(iVar7 + 0x1e));
  if ((uVar4 != 0) || (DAT_803de960 != 0)) {
    piVar5 = ObjGroup_GetObjects(0x24,local_28);
    ObjMsg_SendToObjects(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,3,uVar2,0x11,0,
                 param_14,param_15,param_16);
    while (iVar6 = local_28[0] + -1, bVar1 = local_28[0] != 0, local_28[0] = iVar6, bVar1) {
      iVar6 = *piVar5;
      piVar5 = piVar5 + 1;
      ObjGroup_RemoveObject(iVar6,0x24);
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_802035a8
 * EN v1.0 Address: 0x802035A8
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x80204564
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802035a8(int param_1)
{
  ObjGroup_RemoveObject(param_1,0x1e);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_802035cc
 * EN v1.0 Address: 0x802035CC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x80204588
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802035cc(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_802035f4
 * EN v1.0 Address: 0x802035F4
 * EN v1.0 Size: 148b
 * EN v1.1 Address: 0x802045BC
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802035f4(int param_1)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x4c);
  uVar1 = FUN_80017690((int)*(short *)(iVar2 + 0x1e));
  if (uVar1 == 0) {
    uVar1 = FUN_80017690((int)*(short *)(iVar2 + 0x20));
    if (uVar1 != 0) {
      (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar2 + 0x19),param_1,0xffffffff);
    }
  }
  else {
    FUN_80017ad0(param_1);
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80203688
 * EN v1.0 Address: 0x80203688
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80204650
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80203688(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020368c
 * EN v1.0 Address: 0x8020368C
 * EN v1.0 Size: 860b
 * EN v1.1 Address: 0x802046D0
 * EN v1.1 Size: 648b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020368c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  uint uVar1;
  int iVar2;
  uint uVar3;
  char cVar4;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  short sVar5;
  undefined2 *puVar6;
  undefined2 *puVar7;
  undefined8 extraout_f1;
  undefined8 uVar8;
  
  uVar1 = FUN_80286840();
  puVar7 = *(undefined2 **)(uVar1 + 0xb8);
  uVar8 = extraout_f1;
  iVar2 = FUN_80017a98();
  if (DAT_803dcdeb != '\0') {
    FUN_80017698(0x2d,1);
    FUN_80017698(0x1d7,1);
    puVar6 = &DAT_8032a488;
    for (sVar5 = 0; sVar5 < 9; sVar5 = sVar5 + 1) {
      uVar3 = randomGetRange(1,4);
      *puVar6 = (short)uVar3;
      puVar6 = puVar6 + 1;
    }
    uVar8 = FUN_80017698(0x5e4,0);
    *puVar7 = 0;
    DAT_803dcdeb = '\0';
  }
  uVar3 = FUN_80017690(0x5e3);
  if (((uVar3 == 0) && (uVar3 = FUN_80017690(0x5e0), uVar3 != 0)) &&
     (uVar3 = FUN_80017690(0x5e1), uVar3 != 0)) {
    FUN_80006824(uVar1,SFXmn_spithit6);
    uVar8 = FUN_80017698(0x5e3,1);
  }
  uVar3 = FUN_80017690(0x792);
  if (((uVar3 == 0) && (uVar3 = FUN_80017690(0xb8c), uVar3 != 0)) &&
     (uVar3 = FUN_80017690(0xb8c), uVar3 != 0)) {
    FUN_80006824(uVar1,SFXmn_spithit6);
    uVar8 = FUN_80017698(0x792,1);
  }
  uVar3 = FUN_80017690(0xe58);
  if (uVar3 == 0) {
    uVar3 = FUN_80017690(0x635);
    if ((uVar3 == 0) || (*(char *)(puVar7 + 3) != '\0')) {
      uVar3 = FUN_80017690(0x635);
      if ((uVar3 == 0) && (*(char *)(puVar7 + 3) == '\x01')) {
        *(undefined *)(puVar7 + 3) = 0;
        uVar8 = FUN_80017698(0x5e4,0);
      }
    }
    else {
      FUN_80006824(0,SFXfoot_wood_run_2);
      puVar6 = &DAT_8032a488;
      for (sVar5 = 0; sVar5 < 9; sVar5 = sVar5 + 1) {
        uVar3 = randomGetRange(1,4);
        *puVar6 = (short)uVar3;
        puVar6 = puVar6 + 1;
      }
      uVar8 = FUN_80017698(0x5e4,1);
      *(undefined *)(puVar7 + 3) = 1;
    }
    uVar3 = FUN_80017690(0x5e5);
    if (uVar3 != 0) {
      *puVar7 = 300;
      ObjMsg_SendToObject(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2,0x60005,uVar1
                   ,0,in_r7,in_r8,in_r9,in_r10);
    }
  }
  uVar3 = FUN_80017690(0x7a1);
  if ((uVar3 != 0) &&
     (cVar4 = (**(code **)(*DAT_803dd72c + 0x4c))((int)*(char *)(uVar1 + 0xac),6), cVar4 == '\0')) {
    (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(uVar1 + 0xac),6,1);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_802039e8
 * EN v1.0 Address: 0x802039E8
 * EN v1.0 Size: 660b
 * EN v1.1 Address: 0x80204958
 * EN v1.1 Size: 460b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802039e8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  uint uVar1;
  int iVar2;
  uint uVar3;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  short sVar4;
  undefined2 *puVar5;
  undefined2 *puVar6;
  undefined8 extraout_f1;
  undefined8 uVar7;
  
  uVar1 = FUN_80286840();
  puVar6 = *(undefined2 **)(uVar1 + 0xb8);
  uVar7 = extraout_f1;
  iVar2 = FUN_80017a98();
  if (DAT_803dcdea != '\0') {
    puVar5 = &DAT_8032a488;
    DAT_8032a494 = 0;
    DAT_8032a496 = 0;
    DAT_8032a498 = 0;
    for (sVar4 = 0; sVar4 < 6; sVar4 = sVar4 + 1) {
      uVar3 = randomGetRange(1,4);
      *puVar5 = (short)uVar3;
      puVar5 = puVar5 + 1;
    }
    uVar7 = FUN_80017698(0x5e4,0);
    *puVar6 = 0;
    DAT_803dcdea = '\0';
  }
  uVar3 = FUN_80017690(0x5e3);
  if (((uVar3 == 0) && (uVar3 = FUN_80017690(0x5e0), uVar3 != 0)) &&
     (uVar3 = FUN_80017690(0x5e1), uVar3 != 0)) {
    uVar7 = FUN_80017698(0x5e3,1);
  }
  uVar3 = FUN_80017690(0xe57);
  if (uVar3 == 0) {
    uVar3 = FUN_80017690(0x635);
    if ((uVar3 == 0) || (*(char *)(puVar6 + 3) != '\0')) {
      uVar3 = FUN_80017690(0x635);
      if ((uVar3 == 0) && (*(char *)(puVar6 + 3) == '\x01')) {
        *(undefined *)(puVar6 + 3) = 0;
        uVar7 = FUN_80017698(0x5e4,0);
      }
    }
    else {
      FUN_80006824(0,0x447);
      puVar5 = &DAT_8032a488;
      for (sVar4 = 0; sVar4 < 6; sVar4 = sVar4 + 1) {
        uVar3 = randomGetRange(1,4);
        *puVar5 = (short)uVar3;
        puVar5 = puVar5 + 1;
      }
      uVar7 = FUN_80017698(0x5e4,1);
      *(undefined *)(puVar6 + 3) = 1;
    }
    uVar3 = FUN_80017690(0x5e5);
    if (uVar3 != 0) {
      *puVar6 = 300;
      ObjMsg_SendToObject(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2,0x60005,uVar1
                   ,1,in_r7,in_r8,in_r9,in_r10);
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80203c7c
 * EN v1.0 Address: 0x80203C7C
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x80204B24
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80203c7c(int param_1)
{
  short sVar1;
  int iVar2;
  short *psVar3;
  
  psVar3 = *(short **)(param_1 + 0xb8);
  iVar2 = FUN_80017a98();
  sVar1 = *psVar3;
  if (0 < sVar1) {
    *psVar3 = sVar1 - (short)(int)lbl_803DC074;
    FUN_80294c44(iVar2,0x51e);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80203cdc
 * EN v1.0 Address: 0x80203CDC
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x80204BF0
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80203cdc(int param_1)
{
  ObjGroup_RemoveObject(param_1,9);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80203d00
 * EN v1.0 Address: 0x80203D00
 * EN v1.0 Size: 728b
 * EN v1.1 Address: 0x80204C1C
 * EN v1.1 Size: 524b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80203d00(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  byte bVar6;
  int iVar7;
  undefined8 extraout_f1;
  double dVar8;
  
  iVar1 = FUN_8028683c();
  iVar7 = *(int *)(iVar1 + 0xb8);
  iVar2 = FUN_80017a98();
  uVar3 = FUN_80017690(0xd5d);
  uVar4 = FUN_80017690(0xd59);
  uVar5 = FUN_80017690(0xd5a);
  if (((((uVar3 & 0xff) != 0) && (-1 < *(char *)(iVar7 + 7))) ||
      (((uVar4 & 0xff) != 0 && ((*(byte *)(iVar7 + 7) >> 6 & 1) == 0)))) ||
     (((uVar5 & 0xff) != 0 && ((*(byte *)(iVar7 + 7) >> 5 & 1) == 0)))) {
    FUN_80006824(0,SFXsp_lf_mutter4);
  }
  *(byte *)(iVar7 + 7) = (byte)((uVar3 & 0xff) << 7) | *(byte *)(iVar7 + 7) & 0x7f;
  *(byte *)(iVar7 + 7) = (byte)((uVar4 & 0xff) << 6) & 0x40 | *(byte *)(iVar7 + 7) & 0xbf;
  *(byte *)(iVar7 + 7) = (byte)((uVar5 & 0xff) << 5) & 0x20 | *(byte *)(iVar7 + 7) & 0xdf;
  uVar3 = FUN_80017690(0x5e8);
  if (((uVar3 == 0) && (uVar3 = FUN_80017690(0x5ee), uVar3 != 0)) &&
     (uVar3 = FUN_80017690(0x5ef), uVar3 != 0)) {
    FUN_80017698(0x5e8,1);
  }
  dVar8 = (double)*(float *)(iVar2 + 0x14);
  FUN_8005b024();
  bVar6 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(iVar1 + 0xac));
  if (bVar6 == 2) {
    FUN_8020368c(extraout_f1,dVar8,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  else if ((bVar6 < 2) && (bVar6 != 0)) {
    if ((DAT_803dcde8 != 0) &&
       (DAT_803dcde8 = DAT_803dcde8 - (short)(int)lbl_803DC074, DAT_803dcde8 < 1)) {
      DAT_803dcde8 = 0;
    }
    FUN_802039e8(extraout_f1,dVar8,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  SH_LevelControl_runBloopEvent(iVar7 + 8,2,-1,-1,0xdce,(int *)0x95);
  FUN_801d8480(iVar7 + 8,4,-1,-1,0xdce,(int *)0x37);
  FUN_801d8480(iVar7 + 8,1,-1,-1,0xdce,(int *)0xe4);
  FUN_80017698(0xdcf,0);
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80203fd8
 * EN v1.0 Address: 0x80203FD8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80204E28
 * EN v1.1 Size: 400b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80203fd8(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80203fdc
 * EN v1.0 Address: 0x80203FDC
 * EN v1.0 Size: 156b
 * EN v1.1 Address: 0x80204FB8
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80203fdc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  int iVar1;
  int *piVar2;
  
  piVar2 = *(int **)(param_9 + 0xb8);
  if ((param_10 == 0) && (iVar1 = *piVar2, iVar1 != 0)) {
    FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1);
    *piVar2 = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80204078
 * EN v1.0 Address: 0x80204078
 * EN v1.0 Size: 448b
 * EN v1.1 Address: 0x80205010
 * EN v1.1 Size: 404b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80204078(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  uint uVar1;
  undefined2 *puVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_9 + 0x4c);
  iVar3 = *(int *)(param_9 + 0xb8);
  uVar1 = FUN_80017ae8();
  if (((((uVar1 & 0xff) != 0) && (*(short *)(iVar4 + 0x1a) == 7)) &&
      (*(short *)(iVar3 + 0x10) = *(short *)(iVar3 + 0x10) - (short)(int)lbl_803DC074,
      *(short *)(iVar3 + 0x10) < 1)) &&
     (uVar1 = FUN_80017690((int)*(short *)(iVar3 + 0xc)), uVar1 != 0)) {
    *(undefined2 *)(iVar3 + 0x10) = *(undefined2 *)(iVar3 + 0xe);
    puVar2 = FUN_80017aa4(0x24,0x71b);
    *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(iVar4 + 8);
    *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(iVar4 + 0xc);
    *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(iVar4 + 0x10);
    *(undefined *)(puVar2 + 2) = *(undefined *)(iVar4 + 4);
    *(undefined *)((int)puVar2 + 5) = *(undefined *)(iVar4 + 5);
    *(undefined *)(puVar2 + 3) = *(undefined *)(iVar4 + 6);
    *(undefined *)((int)puVar2 + 7) = *(undefined *)(iVar4 + 7);
    puVar2[0xf] = 0xffff;
    puVar2[0x10] = 0xffff;
    puVar2[0xd] = 0xdc;
    iVar3 = FUN_80017ae4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,
                         *(undefined *)(param_9 + 0xac),0xffffffff,*(uint **)(param_9 + 0x30),in_r8,
                         in_r9,in_r10);
    *(int *)(iVar3 + 0xf4) = (int)*(char *)(iVar4 + 0x1e);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80204238
 * EN v1.0 Address: 0x80204238
 * EN v1.0 Size: 232b
 * EN v1.1 Address: 0x802051A4
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80204238(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9)
{
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar1;
  
  uVar1 = (**(code **)(*DAT_803dd6f8 + 0x18))();
  getLActions(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,0,0,0,0
               ,in_r9,in_r10);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80204320
 * EN v1.0 Address: 0x80204320
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x802051FC
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80204320(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

#pragma scheduling off
#pragma peephole off
void fn_80204320(int obj)
{
  extern void *Obj_GetPlayerObject(void);
  extern uint GameBit_Get(int);
  extern u8 lbl_803DC182;
  extern s16 lbl_80329848[];
  int sub;
  void *player;

  sub = *(int *)(obj + 0xb8);
  player = Obj_GetPlayerObject();
  if (lbl_803DC182 != 0) {
    s16 i;
    s16 *arr = (s16 *)((char *)lbl_80329848 + 12);
    arr[0] = 0;
    arr[1] = 0;
    arr[2] = 0;
    arr = lbl_80329848;
    for (i = 0; i < 6; i++) {
      *arr = (s16)randomGetRange(1, 4);
      arr++;
    }
    GameBit_Set(1508, 0);
    *(s16 *)(sub + 0) = 0;
    lbl_803DC182 = 0;
  }
  if (GameBit_Get(1507) == 0) {
    if (GameBit_Get(1504) != 0 && GameBit_Get(1505) != 0) {
      GameBit_Set(1507, 1);
    }
  }
  if (GameBit_Get(3671) == 0) {
    if (GameBit_Get(1589) != 0 && *(u8 *)(sub + 6) == 0) {
      s16 i;
      s16 *arr;
      Sfx_PlayFromObject(0, 1095);
      arr = lbl_80329848;
      for (i = 0; i < 6; i++) {
        *arr = (s16)randomGetRange(1, 4);
        arr++;
      }
      GameBit_Set(1508, 1);
      *(u8 *)(sub + 6) = 1;
    } else if (GameBit_Get(1589) == 0 && *(u8 *)(sub + 6) == 1) {
      *(u8 *)(sub + 6) = 0;
      GameBit_Set(1508, 0);
    }
    if (GameBit_Get(1509) != 0) {
      *(s16 *)(sub + 0) = 300;
      ObjMsg_SendToObject(player, 0x60005, obj, 1);
    }
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80204348
 * EN v1.0 Address: 0x80204348
 * EN v1.0 Size: 1160b
 * EN v1.1 Address: 0x80205230
 * EN v1.1 Size: 1068b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80204348(uint param_1)
{
  short sVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  uint uVar5;
  bool bVar6;
  int iVar7;
  int iVar8;
  double dVar9;
  
  iVar7 = *(int *)(param_1 + 0x4c);
  iVar8 = *(int *)(param_1 + 0xb8);
  iVar4 = FUN_80017a98();
  fVar2 = lbl_803E7040;
  fVar3 = lbl_803E7038;
  if (iVar4 != 0) {
    sVar1 = *(short *)(iVar8 + 4);
    if (sVar1 == 2) {
      if (*(short *)(iVar8 + 10) == 0) {
        dVar9 = (double)FUN_80017710((float *)(param_1 + 0x18),(float *)(iVar4 + 0x18));
        if ((double)lbl_803E703C <= dVar9) {
          if (*(float *)(iVar7 + 0xc) <= *(float *)(iVar4 + 0x10)) {
            if ((*(float *)(iVar7 + 0xc) < *(float *)(iVar4 + 0x10)) &&
               (*(undefined2 *)(iVar8 + 4) = 4, *(char *)(iVar8 + 0xd) == '\x01')) {
              *(undefined *)(iVar8 + 0xd) = 0;
            }
          }
          else {
            *(undefined2 *)(iVar8 + 4) = 3;
            if (*(char *)(iVar8 + 0xd) == '\x01') {
              *(undefined *)(iVar8 + 0xd) = 0;
            }
          }
        }
        else if (*(float *)(param_1 + 0x10) == lbl_803E7038 + *(float *)(iVar7 + 0xc)) {
          *(undefined2 *)(iVar8 + 4) = 3;
          bVar6 = FUN_800067f0(param_1,8);
          if (!bVar6) {
            FUN_80006824(param_1,SFXfoot_water_run_1);
            *(undefined *)(iVar8 + 0xd) = 1;
          }
        }
        else if (*(float *)(param_1 + 0x10) == *(float *)(iVar7 + 0xc) - lbl_803E7040) {
          *(undefined2 *)(iVar8 + 4) = 4;
          bVar6 = FUN_800067f0(param_1,8);
          if (!bVar6) {
            FUN_80006824(param_1,SFXfoot_water_run_1);
            *(undefined *)(iVar8 + 0xd) = 1;
          }
        }
      }
      else {
        *(short *)(iVar8 + 10) = *(short *)(iVar8 + 10) - (short)(int)lbl_803DC074;
        if (*(short *)(iVar8 + 10) < 1) {
          *(undefined2 *)(iVar8 + 10) = 0;
        }
      }
    }
    else if (sVar1 < 2) {
      if (sVar1 == 0) {
        uVar5 = FUN_80017690((int)*(short *)(iVar8 + 6));
        if (((uVar5 == 0) || (*(char *)(iVar8 + 0xc) == '\x01')) ||
           (dVar9 = (double)FUN_80017710((float *)(param_1 + 0x18),(float *)(iVar4 + 0x18)),
           (double)lbl_803E7034 <= dVar9)) {
          if (((*(char *)(iVar8 + 0xc) == '\x01') &&
              (dVar9 = (double)FUN_80017710((float *)(param_1 + 0x18),(float *)(iVar4 + 0x18)),
              fVar2 = lbl_803E7038, dVar9 < (double)lbl_803E7034)) &&
             (*(float *)(param_1 + 0x10) < lbl_803E7038 + *(float *)(iVar7 + 0xc))) {
            *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) + lbl_803DC074;
            fVar2 = fVar2 + *(float *)(iVar7 + 0xc);
            if (fVar2 <= *(float *)(param_1 + 0x10)) {
              *(float *)(param_1 + 0x10) = fVar2;
              *(undefined2 *)(iVar8 + 4) = 1;
            }
          }
        }
        else if (*(float *)(param_1 + 0x10) < lbl_803E7038 + *(float *)(iVar7 + 0xc)) {
          bVar6 = FUN_800067f0(param_1,8);
          if (!bVar6) {
            FUN_80006824(param_1,SFXsp_lfoot_taunt6);
            *(undefined *)(iVar8 + 0xd) = 1;
          }
          *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) + lbl_803DC074;
          fVar2 = lbl_803E7038 + *(float *)(iVar7 + 0xc);
          if (fVar2 <= *(float *)(param_1 + 0x10)) {
            *(float *)(param_1 + 0x10) = fVar2;
            *(undefined2 *)(iVar8 + 4) = 1;
            FUN_8000680c(param_1,8);
          }
        }
      }
      else if (-1 < sVar1) {
        *(undefined2 *)(iVar8 + 4) = 2;
        *(undefined2 *)(iVar8 + 10) = 100;
      }
    }
    else if (sVar1 == 4) {
      if (lbl_803E7038 + *(float *)(iVar7 + 0xc) <= *(float *)(param_1 + 0x10)) {
        *(undefined2 *)(iVar8 + 4) = 2;
        *(undefined2 *)(iVar8 + 10) = 100;
        FUN_8000680c(param_1,8);
        FUN_80017710((float *)(param_1 + 0x18),(float *)(iVar4 + 0x18));
      }
      else {
        *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) + lbl_803DC074;
        fVar3 = fVar3 + *(float *)(iVar7 + 0xc);
        if (fVar3 <= *(float *)(param_1 + 0x10)) {
          *(float *)(param_1 + 0x10) = fVar3;
          *(undefined2 *)(iVar8 + 4) = 2;
          *(undefined2 *)(iVar8 + 10) = 100;
          FUN_8000680c(param_1,8);
        }
        FUN_80017710((float *)(param_1 + 0x18),(float *)(iVar4 + 0x18));
      }
    }
    else if (sVar1 < 4) {
      if (*(float *)(param_1 + 0x10) <= *(float *)(iVar7 + 0xc) - lbl_803E7040) {
        FUN_8000680c(param_1,8);
        FUN_80017710((float *)(param_1 + 0x18),(float *)(iVar4 + 0x18));
        *(undefined2 *)(iVar8 + 4) = 2;
        *(undefined2 *)(iVar8 + 10) = 100;
      }
      else {
        *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) - lbl_803DC074;
        fVar2 = *(float *)(iVar7 + 0xc) - fVar2;
        if (*(float *)(param_1 + 0x10) <= fVar2) {
          *(float *)(param_1 + 0x10) = fVar2;
          *(undefined2 *)(iVar8 + 4) = 2;
          FUN_8000680c(param_1,8);
          *(undefined2 *)(iVar8 + 10) = 100;
        }
        FUN_80017710((float *)(param_1 + 0x18),(float *)(iVar4 + 0x18));
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_802047d0
 * EN v1.0 Address: 0x802047D0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020565C
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802047d0(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802047d4
 * EN v1.0 Address: 0x802047D4
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x8020570C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802047d4(void)
{
  FUN_800723a0();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_802047f4
 * EN v1.0 Address: 0x802047F4
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x80205740
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802047f4(void)
{
  FUN_800723a0();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80204814
 * EN v1.0 Address: 0x80204814
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x8020576C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80204814(void)
{
  FUN_800723a0();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80204834
 * EN v1.0 Address: 0x80204834
 * EN v1.0 Size: 896b
 * EN v1.1 Address: 0x802057A0
 * EN v1.1 Size: 696b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80204834(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,int param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  short sVar1;
  int iVar2;
  char cVar4;
  undefined4 uVar3;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  undefined8 uVar9;
  
  iVar2 = FUN_80286840();
  iVar8 = *(int *)(iVar2 + 0xb8);
  iVar7 = *(int *)(iVar2 + 0x4c);
  *(undefined2 *)(param_11 + 0x70) = 0xffff;
  *(undefined *)(param_11 + 0x56) = 0;
  for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar6 = iVar6 + 1) {
    sVar1 = *(short *)(iVar8 + 8);
    if (sVar1 == 10) {
      if (*(char *)(param_11 + iVar6 + 0x81) == '\x14') {
        if (*(int *)(iVar7 + 0x14) == 0x49de8) {
          *(byte *)(iVar8 + 0xf) = *(byte *)(iVar8 + 0xf) & 0x7f | 0x80;
        }
        else {
          cVar4 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(iVar2 + 0xac));
          if ((cVar4 == '\x01') ||
             (cVar4 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(iVar2 + 0xac)),
             cVar4 == '\x02')) {
            FUN_80042b9c(0,0,1);
            uVar3 = FUN_80044404(0x32);
            FUN_80042bec(uVar3,0);
            iVar5 = *DAT_803dd72c;
            uVar9 = (**(code **)(iVar5 + 0x44))(0x32,2);
            FUN_80053c98(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x73,'\0',
                         iVar5,param_12,param_13,param_14,param_15,param_16);
          }
        }
      }
    }
    else if (((sVar1 < 10) && (sVar1 == 1)) && (*(char *)(param_11 + iVar6 + 0x81) == '\x01')) {
      cVar4 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(iVar2 + 0xac));
      if (cVar4 == '\x01') {
        (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(iVar2 + 0xac),5,0);
        (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(iVar2 + 0xac),6,0);
        param_12 = *DAT_803dd72c;
        (**(code **)(param_12 + 0x50))((int)*(char *)(iVar2 + 0xac),7,0);
      }
      else {
        cVar4 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(iVar2 + 0xac));
        if (cVar4 == '\x02') {
          (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(iVar2 + 0xac),5,0);
          (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(iVar2 + 0xac),6,0);
          param_12 = *DAT_803dd72c;
          (**(code **)(param_12 + 0x50))((int)*(char *)(iVar2 + 0xac),7,0);
        }
      }
    }
    *(undefined *)(param_11 + iVar6 + 0x81) = 0;
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80204bb4
 * EN v1.0 Address: 0x80204BB4
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x80205A58
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80204bb4(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80204bdc
 * EN v1.0 Address: 0x80204BDC
 * EN v1.0 Size: 832b
 * EN v1.1 Address: 0x80205A8C
 * EN v1.1 Size: 732b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80204bdc(int param_1)
{
  byte bVar1;
  int iVar2;
  uint uVar3;
  float *pfVar4;
  double dVar5;
  
  iVar2 = FUN_80017a98();
  pfVar4 = *(float **)(param_1 + 0xb8);
  if (*(char *)((int)pfVar4 + 0xf) < '\0') {
    FUN_80017698(0xef7,1);
    *(byte *)((int)pfVar4 + 0xf) = *(byte *)((int)pfVar4 + 0xf) & 0x7f;
  }
  uVar3 = (uint)*(short *)((int)pfVar4 + 6);
  if (uVar3 != 0xffffffff) {
    if (*(char *)((int)pfVar4 + 0xd) != '\0') {
      uVar3 = FUN_80017690(uVar3);
      if (uVar3 != 0) {
        return;
      }
      FUN_80017698((int)*(short *)((int)pfVar4 + 6),1);
      *(undefined *)((int)pfVar4 + 0xd) = 1;
      return;
    }
    uVar3 = FUN_80017690(uVar3);
    if (uVar3 != 0) {
      *(undefined *)((int)pfVar4 + 0xd) = 1;
      return;
    }
  }
  if (*(char *)((int)pfVar4 + 0xd) == '\0') {
    bVar1 = *(byte *)((int)pfVar4 + 0xe);
    if (bVar1 == 3) {
      dVar5 = (double)FUN_8001771c((float *)(param_1 + 0x18),(float *)(iVar2 + 0x18));
      if (((dVar5 < (double)*pfVar4) && ((int)*(short *)(pfVar4 + 1) != 0xffffffff)) &&
         (uVar3 = FUN_80017690((int)*(short *)(pfVar4 + 1)), uVar3 == 0)) {
        (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(short *)(pfVar4 + 2),param_1,0xffffffff);
        FUN_80017698((int)*(short *)(pfVar4 + 1),1);
        *(undefined *)((int)pfVar4 + 0xd) = 1;
      }
    }
    else if (bVar1 < 3) {
      if (bVar1 == 1) {
        if (((int)*(short *)(pfVar4 + 1) != 0xffffffff) &&
           (uVar3 = FUN_80017690((int)*(short *)(pfVar4 + 1)), uVar3 != 0)) {
          (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(short *)(pfVar4 + 2),param_1,0xffffffff);
          *(undefined *)((int)pfVar4 + 0xd) = 1;
        }
      }
      else if (bVar1 == 0) {
        dVar5 = (double)FUN_8001771c((float *)(param_1 + 0x18),(float *)(iVar2 + 0x18));
        if (dVar5 < (double)*pfVar4) {
          (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(short *)(pfVar4 + 2),param_1,0xffffffff);
          *(undefined *)((int)pfVar4 + 0xd) = 1;
        }
      }
      else {
        dVar5 = (double)FUN_8001771c((float *)(param_1 + 0x18),(float *)(iVar2 + 0x18));
        if (((dVar5 < (double)*pfVar4) && ((int)*(short *)(pfVar4 + 1) != 0xffffffff)) &&
           (uVar3 = FUN_80017690((int)*(short *)(pfVar4 + 1)), uVar3 != 0)) {
          (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(short *)(pfVar4 + 2),param_1,0xffffffff);
          *(undefined *)((int)pfVar4 + 0xd) = 1;
        }
      }
    }
    else if (bVar1 == 5) {
      if (((int)*(short *)(pfVar4 + 1) != 0xffffffff) &&
         (uVar3 = FUN_80017690((int)*(short *)(pfVar4 + 1)), uVar3 != 0)) {
        (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(short *)(pfVar4 + 2),param_1,0xffffffff);
      }
    }
    else if (((bVar1 < 5) && ((int)*(short *)(pfVar4 + 1) != 0xffffffff)) &&
            (uVar3 = FUN_80017690((int)*(short *)(pfVar4 + 1)), uVar3 == 0)) {
      (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(short *)(pfVar4 + 2),param_1,0xffffffff);
      FUN_80017698((int)*(short *)(pfVar4 + 1),1);
      *(undefined *)((int)pfVar4 + 0xd) = 1;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80204f1c
 * EN v1.0 Address: 0x80204F1C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80205D68
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80204f1c(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80204f20
 * EN v1.0 Address: 0x80204F20
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x80205E14
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80204f20(undefined4 param_1)
{
  (**(code **)(*DAT_803dd6fc + 0x18))();
  (**(code **)(*DAT_803dd6f8 + 0x18))(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80204f7c
 * EN v1.0 Address: 0x80204F7C
 * EN v1.0 Size: 612b
 * EN v1.1 Address: 0x80205E68
 * EN v1.1 Size: 612b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80204f7c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  float fVar1;
  undefined2 *puVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  double dVar6;
  undefined8 uVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined4 auStack_78 [2];
  short asStack_70 [4];
  short asStack_68 [4];
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  undefined auStack_3c [12];
  float local_30;
  float local_2c;
  float local_28;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  if (visible == '\0') {
    *(undefined2 *)(iVar5 + 4) = 0;
    *(undefined *)(iVar5 + 8) = 0;
  }
  else {
    FUN_8003b818(param_1);
    if (*(char *)(iVar5 + 10) != '\0') {
      *(undefined *)(iVar5 + 8) = 1;
      puVar2 = FUN_800069a8();
      local_48 = *(float *)(puVar2 + 6) - *(float *)(param_1 + 0xc);
      local_44 = *(float *)(puVar2 + 8) - *(float *)(param_1 + 0x10);
      local_40 = *(float *)(puVar2 + 10) - *(float *)(param_1 + 0x14);
      dVar6 = FUN_80293900((double)(local_40 * local_40 + local_48 * local_48 + local_44 * local_44)
                          );
      if ((double)lbl_803E7064 < dVar6) {
        fVar1 = (float)((double)lbl_803E7060 / dVar6);
        local_48 = local_48 * fVar1;
        dVar12 = (double)local_48;
        local_44 = local_44 * fVar1;
        dVar11 = (double)local_44;
        local_40 = local_40 * fVar1;
        dVar10 = (double)local_40;
        dVar6 = (double)lbl_803E7068;
        local_54 = (float)(dVar6 * dVar12) + *(float *)(param_1 + 0xc);
        local_50 = (float)(dVar6 * dVar11) + *(float *)(param_1 + 0x10);
        local_4c = (float)(dVar6 * dVar10) + *(float *)(param_1 + 0x14);
        dVar6 = (double)lbl_803E706C;
        dVar9 = (double)(float)(dVar6 * dVar12);
        dVar8 = (double)(float)(dVar6 * dVar11);
        local_60 = (float)(dVar9 + (double)*(float *)(puVar2 + 6));
        local_5c = (float)(dVar8 + (double)*(float *)(puVar2 + 8));
        local_58 = (float)(dVar6 * dVar10) + *(float *)(puVar2 + 10);
        FUN_80006a68(&local_54,asStack_68);
        uVar7 = FUN_80006a68(&local_60,asStack_70);
        iVar3 = FUN_80006a64(uVar7,dVar8,dVar9,dVar10,dVar11,dVar12,in_f7,in_f8,asStack_68,
                             asStack_70,auStack_78,(undefined *)0x0,0);
        if (iVar3 == 0) {
          *(undefined *)(iVar5 + 8) = 0;
          (**(code **)(*DAT_803dd6f8 + 0x14))(param_1);
        }
      }
      if (*(short *)(iVar5 + 4) < 1) {
        if (*(char *)(iVar5 + 8) != '\0') {
          local_30 = lbl_803E7070;
          local_2c = lbl_803E7074;
          local_28 = lbl_803E7070;
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x1f7,auStack_3c,0x12,0xffffffff,0);
        }
        uVar4 = randomGetRange(0xfffffff6,10);
        *(short *)(iVar5 + 4) = (short)uVar4 + 0x3c;
      }
      else {
        *(short *)(iVar5 + 4) = *(short *)(iVar5 + 4) - (short)(int)lbl_803DC074;
      }
    }
  }
  return;
}

#pragma scheduling off
#pragma peephole off
void dll_22C_init(int obj, char *p)
{
  extern int dll_22C_SeqFn(void);
  extern f32 lbl_803E63A8;
  int b8;

  b8 = *(int *)(obj + 0xb8);
  *(int *)(obj + 0xbc) = (int)dll_22C_SeqFn;
  *(s16 *)(obj + 0) = (s16)(*(char *)(p + 0x18) << 8);
  *(s16 *)(b8 + 4) = 0;
  *(s16 *)(b8 + 6) = *(s16 *)(p + 0x20);
  *(s16 *)(b8 + 8) = *(s16 *)(p + 0x1e);
  *(f32 *)(b8 + 0) = (f32)*(s16 *)(p + 0x1a);
  *(u8 *)(b8 + 12) = (u8)*(s16 *)(p + 0x1c);
  *(f32 *)(obj + 0x10) = *(f32 *)(obj + 0x10) - lbl_803E63A8;
  *(u16 *)(obj + 0xb0) = *(u16 *)(obj + 0xb0) | 0x2000;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_802051e0
 * EN v1.0 Address: 0x802051E0
 * EN v1.0 Size: 824b
 * EN v1.1 Address: 0x802060CC
 * EN v1.1 Size: 888b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802051e0(uint param_1)
{
  int iVar1;
  int *piVar2;
  uint uVar3;
  uint *puVar4;
  undefined4 local_48;
  int local_44;
  int local_40;
  undefined4 local_3c;
  undefined auStack_38 [16];
  float local_28;
  longlong local_20;
  
  puVar4 = *(uint **)(param_1 + 0xb8);
  local_48 = DAT_802c2c90;
  local_44 = DAT_802c2c94;
  local_40 = DAT_802c2c98;
  local_3c = DAT_802c2c9c;
  FUN_80006824(param_1,SFXmn_eggylaugh216);
  FUN_80057690(param_1);
  if (*(char *)((int)puVar4 + 9) == '\x01') {
    local_28 = lbl_803E7078;
    *(undefined *)(puVar4 + 3) = *(undefined *)((int)puVar4 + 10);
    iVar1 = ObjHits_GetPriorityHit(param_1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
    if ((iVar1 != 0) &&
       (*(char *)((int)puVar4 + 10) = '\x01' - *(char *)((int)puVar4 + 10),
       *(char *)((int)puVar4 + 10) != '\0')) {
      *(undefined2 *)((int)puVar4 + 6) = 2000;
    }
    if ((*(char *)((int)puVar4 + 10) != '\0') && (*(short *)((int)puVar4 + 6) != 0)) {
      local_20 = (longlong)(int)lbl_803DC074;
      *(short *)((int)puVar4 + 6) = *(short *)((int)puVar4 + 6) - (short)(int)lbl_803DC074;
      if (*(short *)((int)puVar4 + 6) < 1) {
        *(undefined2 *)((int)puVar4 + 6) = 0;
        *(undefined *)((int)puVar4 + 10) = 0;
      }
    }
    if (((*(char *)((int)puVar4 + 10) != '\0') && (*(short *)(puVar4 + 1) < 1)) &&
       (*(char *)((int)puVar4 + 0xb) != '\0')) {
      *(undefined *)((int)puVar4 + 0xb) = 0;
      FUN_80006824(param_1,SFXmn_sml_trex_snap1);
    }
    if (*(char *)((int)puVar4 + 10) != *(char *)(puVar4 + 3)) {
      if (*(char *)((int)puVar4 + 10) == '\0') {
        FUN_8000680c(param_1,0x40);
        (**(code **)(*DAT_803dd6fc + 0x18))(param_1);
        (**(code **)(*DAT_803dd6f8 + 0x14))(param_1);
        if ((*puVar4 != 0xffffffff) && (uVar3 = FUN_80017690(*puVar4), uVar3 != 0)) {
          FUN_80017698(*puVar4,0);
        }
        if ((DAT_803de968 == '\x01') && (*(char *)((int)puVar4 + 0xd) == '\0')) {
          DAT_803de968 = '\0';
        }
        if (((DAT_803de968 == '\x02') && (*(char *)((int)puVar4 + 0xd) == '\x01')) &&
           (uVar3 = FUN_80017690(0x5e2), uVar3 == 0)) {
          FUN_80017698(0x5e2,0);
          DAT_803de968 = '\0';
        }
      }
      else {
        piVar2 = (int *)FUN_80006b14(0x69);
        local_40 = (uint)*(byte *)((int)puVar4 + 0xd) * 2;
        local_44 = local_40 + 0x19d;
        local_40 = local_40 + 0x19e;
        (**(code **)(*piVar2 + 4))(param_1,1,auStack_38,0x10004,0xffffffff,&local_48);
        FUN_80006b0c((undefined *)piVar2);
        iVar1 = 0;
        do {
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x1a3,0,0,0xffffffff,0);
          iVar1 = iVar1 + 1;
        } while (iVar1 < 100);
        if ((*puVar4 != 0xffffffff) && (uVar3 = FUN_80017690(*puVar4), uVar3 == 0)) {
          FUN_80017698(*puVar4,1);
        }
        if (((DAT_803de968 == '\0') && (*(char *)((int)puVar4 + 0xd) == '\0')) &&
           (uVar3 = FUN_80017690(*puVar4), uVar3 != 0)) {
          DAT_803de968 = '\x01';
        }
        if (((DAT_803de968 == '\x01') && (*(char *)((int)puVar4 + 0xd) == '\x01')) &&
           (uVar3 = FUN_80017690(*puVar4), uVar3 != 0)) {
          FUN_80017698(0x5e2,1);
          DAT_803de968 = '\x02';
        }
        *(undefined *)((int)puVar4 + 0xb) = 1;
        *(undefined2 *)(puVar4 + 1) = 1;
      }
    }
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void dbegg_release(void) {}
void dbegg_initialise(void) {}
void GCRobotBlast_free(void) {}
void GCRobotBlast_render(void) {}
void GCRobotBlast_hitDetect(void) {}
void GCRobotBlast_update(void) {}
void GCRobotBlast_release(void) {}
void GCRobotBlast_initialise(void) {}
void DrakorEnergy_func0B_nop(void) {}
void drakorenergy_free(void) {}
void drakorenergy_hitDetect(void) {}
void drakorenergy_release(void) {}
void drakorenergy_initialise(void) {}

extern f32 lbl_803E627C;
extern f32 lbl_803E62A0;

#pragma scheduling off
#pragma peephole off
void drakorenergy_init(int *obj, u8 *init) {
    extern uint GameBit_Get(int);
    u8 *sub;
    f32 fz;
    sub = *(u8**)((char*)obj + 0xb8);
    sub[8] = 5;
    *(f32*)((char*)obj + 0xc) = *(f32*)(init + 8);
    *(f32*)((char*)obj + 0x10) = *(f32*)(init + 0xc);
    *(f32*)((char*)obj + 0x14) = *(f32*)(init + 0x10);
    fz = lbl_803E627C;
    *(f32*)((char*)obj + 0x2c) = fz;
    *(f32*)((char*)obj + 0x24) = fz;
    *(f32*)((char*)obj + 0x28) = lbl_803E62A0;
    *(int*)(sub + 4) = randomGetRange(0, 0xffff);
    if (GameBit_Get(*(s16*)(init + 0x20)) != 0) {
        sub[8] = 4;
    }
}
#pragma peephole reset
#pragma scheduling reset
void dbstealerworm_release(void) {}
void dbholecontrol1_hitDetect(void) {}
void dbholecontrol1_release(void) {}
void dbholecontrol1_initialise(void) {}

extern void objRemoveFromListFn_8002ce88(int *obj);

#pragma scheduling off
#pragma peephole off
void dbholecontrol1_update(int *obj) {
    extern int *gObjectTriggerInterface;
    extern uint GameBit_Get(int);
    u8 *def;
    def = *(u8**)((char*)obj + 0x4c);
    if (GameBit_Get(*(s16*)(def + 0x1e)) != 0) {
        objRemoveFromListFn_8002ce88(obj);
        *(s16*)((char*)obj + 6) = (s16)(*(s16*)((char*)obj + 6) | 0x4000);
    } else if (GameBit_Get(*(s16*)(def + 0x20)) != 0) {
        ((void(*)(int, int*, int))((void**)*(int*)gObjectTriggerInterface)[18])(*(s8*)(def + 0x19), obj, -1);
    }
}
#pragma peephole reset
#pragma scheduling reset

extern int dbholecontrol1_SeqFn(int obj, int unused, int p3);
extern void Stack_Free(int *stack);
extern void Obj_FreeObject(int obj);
extern void **gBaddieControlInterface;
extern int *gPlayerInterface;
extern f32 lbl_803E62A8;
extern f32 lbl_803E62FC;
extern u8 lbl_80329514[];
extern void *memset(void *dst, int v, int n);
extern void ObjAnim_SetCurrentMove(void *obj, int move, f32 weight, int flag);

#pragma scheduling off
#pragma peephole off
void dbstealerworm_init(int *obj, u8 *def, int param3) {
    u8 *sub;
    int *p40c;
    int mode;
    int r;

    sub = *(u8**)((char*)obj + 0xb8);
    mode = 6;
    if (param3 != 0) {
        mode = (u8)(mode | 1);
    }
    ((void(*)(int*, u8*, u8*, int, int, int, u8, f32))((void**)*gBaddieControlInterface)[22])(obj, def, sub, 0x10, 7, 0x10a, mode, lbl_803E62FC);
    ObjGroup_AddObject(obj, 3);
    *(int*)((char*)obj + 0xbc) = 0;
    p40c = *(int**)(sub + 0x40c);
    memset(p40c, 0, 0x50);
    *(f32*)((char*)p40c + 8) = lbl_803E62FC;
    *(int*)p40c = (int)&lbl_80329514[((s16)*(s16*)(def + 0x24)) * 8];
    r = randomGetRange(0xa, 0x12c);
    *(f32*)((char*)p40c + 0xc) = (f32)(s32)r;
    *(u8*)((char*)p40c + 0x44) = (u8)((*(u8*)((char*)p40c + 0x44) & ~0x20) | ((def[0x2b] & 1) << 5));
    *(u8*)((char*)p40c + 0x44) = (u8)(*(u8*)((char*)p40c + 0x44) | 0x10);
    *(int*)((char*)p40c + 0x18) = 0;
    ObjAnim_SetCurrentMove(obj, 8, lbl_803E62A8, 0);
    *(u8*)((char*)obj + 0xaf) = (u8)(*(u8*)((char*)obj + 0xaf) | 0x8);
    ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, sub, 3);
    *(s16*)(sub + 0x270) = 0;
    *(u8*)(sub + 0x25f) = 1;
    ObjHits_EnableObject(obj);
    ObjMsg_AllocQueue(obj, 4);
    if (*(int*)((char*)obj + 0x64) != 0) {
        *(int*)(*(int*)((char*)obj + 0x64) + 0x30) = *(int*)(*(int*)((char*)obj + 0x64) + 0x30) | 0x4008;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void dbstealerworm_free(int *obj) {
    u8 *sub = *(u8**)((char*)obj + 0xb8);
    int *p40c = *(int**)(sub + 0x40c);
    ObjGroup_RemoveObject(obj, 3);
    Stack_Free((int*)p40c[9]);
    if (*(void**)((char*)obj + 0xc8) != NULL) {
        Obj_FreeObject(*(int*)((char*)obj + 0xc8));
        *(int*)((char*)obj + 0xc8) = 0;
    }
    ((void(*)(int*, u8*, int))((void**)*gBaddieControlInterface)[16])(obj, sub, 3);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void dbholecontrol1_init(int *obj, u8 *params) {
    int *sub = *(int**)((char*)obj + 0xb8);
    ObjGroup_AddObject(obj, 0x1e);
    *(s16*)obj = (s16)((s8)params[0x18] << 8);
    *(void**)((char*)obj + 0xbc) = (void*)&dbholecontrol1_SeqFn;
    sub[0] = *(s16*)(params + 0x1a);
    sub[1] = *(s16*)(params + 0x1c);
}
#pragma peephole reset
#pragma scheduling reset
void dfplevelcontrol_render(void) {}
void dfplevelcontrol_hitDetect(void) {}
void dfplevelcontrol_release(void) {}
void dfpobjcreator_hitDetect(void) {}
void dfpobjcreator_release(void) {}
void dfpobjcreator_initialise(void) {}
void dll_22C_hitDetect_nop(void) {}
void dll_22C_release_nop(void) {}
void dll_22C_initialise_nop(void) {}
void doorswitch_render(void) {}
void doorswitch_hitDetect(void) {}
void doorswitch_release(void) {}
void doorswitch_initialise(void) {}
void dfpseqpoint_free(void) {}
void dfpseqpoint_hitDetect(void) {}
void dfpseqpoint_release(void) {}
void dfpseqpoint_initialise(void) {}

extern int dfpseqpoint_SeqFn(int obj, int p2, int p3);

#pragma scheduling off
#pragma peephole off
void dfpseqpoint_init(int *obj, u8 *init) {
    u8 *sub;
    sub = *(u8**)((char*)obj + 0xb8);
    *(void**)((char*)obj + 0xbc) = (void*)&dfpseqpoint_SeqFn;
    *(s16*)obj = (s16)((s8)init[0x18] << 8);
    *(f32*)sub = (f32)(s32)*(s16*)(init + 0x1a);
    *(s16*)(sub + 8) = *(s16*)(init + 0x1c);
    sub[0xe] = init[0x19];
    *(s16*)(sub + 4) = *(s16*)(init + 0x1e);
    *(s16*)(sub + 6) = *(s16*)(init + 0x20);
    *(u16*)((char*)obj + 0xb0) = (u16)(*(u16*)((char*)obj + 0xb0) | 0x2000);
    sub[0xf] = (u8)(sub[0xf] & ~0x80);
}
#pragma peephole reset
#pragma scheduling reset
void DFP_Torch_hitDetect(void) {}
void DFP_Torch_release(void) {}
void DFP_Torch_initialise(void) {}
void chuka_render(void) {}

/* 8b "li r3, N; blr" returners. */
int GCRobotBlast_getExtraSize(void) { return 0x8; }
int GCRobotBlast_getObjectTypeId(void) { return 0x0; }
int drakorenergy_getExtraSize(void) { return 0xc; }
int drakorenergy_getObjectTypeId(void) { return 0x0; }
int dbstealerworm_getExtraSize(void) { return 0x460; }
int dbstealerworm_getObjectTypeId(void) { return 0x49; }
int dbholecontrol1_getExtraSize(void) { return 0xc; }
int dbholecontrol1_getObjectTypeId(void) { return 0x0; }
int dfplevelcontrol_getExtraSize(void) { return 0xc; }
int dfplevelcontrol_getObjectTypeId(void) { return 0x0; }
int dfpobjcreator_getExtraSize(void) { return 0x1c; }
int dfpobjcreator_getObjectTypeId(void) { return 0x0; }
int dll_22C_SeqFn(void) { return 0x0; }
int dll_22C_getExtraSize_ret_16(void) { return 0x10; }
int dll_22C_getObjectTypeId(void) { return 0x0; }
int doorswitch_getExtraSize(void) { return 0x0; }
int doorswitch_getObjectTypeId(void) { return 0x0; }
int dfpseqpoint_getExtraSize(void) { return 0x10; }
int dfpseqpoint_getObjectTypeId(void) { return 0x0; }
int DFP_Torch_getExtraSize(void) { return 0x10; }
int DFP_Torch_getObjectTypeId(void) { return 0x1; }
int chuka_SeqFn(void) { return 0x0; }
int chuka_getExtraSize(void) { return 0xc; }
int chuka_getObjectTypeId(void) { return 0x0; }

/* Pattern wrappers. */
s16 DBstealerworm_setScale(int *obj) { return *(s16*)((char*)((int**)obj)[0xb8/4] + 0x274); }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E6390;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E6398;
extern f32 lbl_803E63B8;
#pragma peephole off
void dbholecontrol1_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E6390); }
void dll_22C_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E6398); }
void dfpseqpoint_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E63B8); }
void dfpobjcreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }
#pragma peephole reset

extern f32 lbl_803E6278;
#pragma scheduling off
#pragma peephole off
void drakorenergy_render(int obj, int p1, int p2, int p3, int p4, s8 visible) {
    u8 *inner = *(u8 **)(obj + 0xb8);
    u32 t = inner[8];
    if (t != 0 && t != 4) {
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p1, p2, p3, p4, lbl_803E6278);
    }
}
#pragma peephole reset
#pragma scheduling reset

extern int *gExpgfxInterface;
extern int *gPlayerInterface;
extern int lbl_803AD0F4[];
extern int GCRobotBlast_SeqFn(int, int, int);
#pragma scheduling off
#pragma peephole off
void chuka_free(int obj) {
    (*(void (*)(int))(*(int *)(*gExpgfxInterface + 0x18)))(obj);
}
void chuka_hitDetect(int obj) {
    int *light;
    int *inner = *(int **)(obj + 0xb8);
    light = (int *)inner[1];
    if (light == NULL) return;
    if ((*(s16 *)((char *)light + 6) & 0x40) == 0) return;
    inner[1] = 0;
}
void dbstealerworm_hitDetect(int obj) {
    int *inner = *(int **)(obj + 0xb8);
    (*(void (*)(int, int *, int *))(*(int *)(*gPlayerInterface + 0xc)))(obj, inner, lbl_803AD0F4);
}
void GCRobotBlast_init(int obj, s8 *p) {
    typedef struct {
        u8 b80 : 1;
    } BlastFlags4;
    char *inner = *(char **)(obj + 0xb8);
    *(int *)inner = (s8)p[0x19];
    ((BlastFlags4 *)(inner + 4))->b80 = 0;
    *(void (**)(void))((char *)obj + 0xbc) = (void (*)(void))GCRobotBlast_SeqFn;
}
#pragma peephole reset
#pragma scheduling reset

/* ObjGroup_RemoveObject(x, N) wrappers. */
#pragma scheduling off
#pragma peephole off
void dbholecontrol1_free(int x) { ObjGroup_RemoveObject(x, 0x1e); }
void dfplevelcontrol_free(int x) { ObjGroup_RemoveObject(x, 0x9); }
#pragma peephole reset
#pragma scheduling reset

/* plain forwarder. */
extern void DBstealerwo_setFuncPtrs_80203c78(void);
void dbstealerworm_initialise(void) { DBstealerwo_setFuncPtrs_80203c78(); }

/* OSReport(string) wrappers. */
extern void OSReport(const char *fmt, ...);
#pragma scheduling off
#pragma peephole off
void doorswitch_free(void) { OSReport(sDoorswitchInitNoLongerSupported); }
void doorswitch_update(void) { OSReport(sDoorswitchInitNoLongerSupported); }
void doorswitch_init(void) { OSReport(sDoorswitchInitNoLongerSupported); }
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int DrakorEnergy_setScale(int *obj) { return *((u8*)((int**)obj)[0xb8/4] + 0x8) == 0; }
#pragma peephole reset
#pragma scheduling reset

/* alpha-flag predicate: returns 7 on fire/clear, 0 on idle */
extern f32 lbl_803E62A8;
#pragma peephole off
#pragma scheduling off
int fn_80200460(int p1, int p2)
{
  f32 fz;
  if (*(void **)(p2 + 0x2d0) != NULL) {
    if ((s8)*(u8 *)(p2 + 0x27b) != 0) {
      fz = lbl_803E62A8;
      *(f32 *)(p2 + 0x284) = fz;
      *(f32 *)(p2 + 0x280) = fz;
      return 7;
    }
    if ((s8)*(u8 *)(p2 + 0x346) != 0) return 7;
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/* baddie anim update: fires vtable[0x13] when flag set */
extern void **gBaddieControlInterface;
#pragma peephole off
#pragma scheduling off
int fn_8020032C(int p1, int p2)
{
  int obj_b8 = *(int *)(p1 + 0xb8);
  if ((s8)*(u8 *)(p2 + 0x27b) != 0) {
    (*(void (**)(int, s16, int, int))((char *)*gBaddieControlInterface + 0x4c))(
        p1, *(s16 *)(obj_b8 + 0x3f0), -1, 0);
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/* anim progress accumulator */
extern f32 lbl_803E62BC;
#pragma peephole off
#pragma scheduling off
int fn_80200410(int p1, int p2)
{
  int obj_b8 = *(int *)(p1 + 0xb8);
  if ((s8)*(u8 *)(p2 + 0x354) < 1) return 3;
  if ((s8)*(u8 *)(p2 + 0x346) != 0) {
    *(f32 *)(*(int *)(obj_b8 + 0x40c) + 0x38) += lbl_803E62BC;
    return 7;
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/* clear list-actions wrapper: notifies vtable[6] then resets getLActions */
#pragma peephole off
#pragma scheduling off
void fn_80204B6C(int p1)
{
  (*(void (**)(int))((char *)*gExpgfxInterface + 0x18))(p1);
  getLActions(p1, p1, 0, 0, 0, 0);
}
#pragma peephole reset
#pragma scheduling reset

/* timed counter: decrement (p1->b8)->0 by timeDelta, then notify */
extern void *Obj_GetPlayerObject(void);
extern void fn_802960E8(void *playerObj, int p2);
extern f32 timeDelta;
#pragma peephole off
#pragma scheduling off
int dfplevelcontrol_SeqFn(int p1)
{
  int p_b8 = *(int *)(p1 + 0xb8);
  void *player = Obj_GetPlayerObject();
  s16 v = *(s16 *)p_b8;
  if (v > 0) {
    *(s16 *)p_b8 = v - (int)timeDelta;
    fn_802960E8(player, 0x51e);
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern s16 lbl_80329848[];
#pragma scheduling off
#pragma peephole off
void dfplevelcontrol_initialise(void) {
    s16 *p = lbl_80329848;
    p[0] = 1;
    p[1] = 2;
    p[2] = 3;
    p[3] = 0;
    p[4] = 0;
    p[5] = 0;
    p[6] = 0;
    p[7] = 0;
    p[8] = 0;
}

extern void Obj_FreeObject(int obj);
void dfpobjcreator_free(int obj, int flag) {
    int *state = *(int **)((char *)obj + 0xB8);
    if (flag == 0) {
        if (*(void **)state != NULL) {
            Obj_FreeObject(*(int *)state);
            *(int *)state = 0;
        }
    }
}

extern void dbegg_setupFromDef(int obj, int *state);
void dbegg_init(int obj) {
    int *q;
    dbegg_setupFromDef(obj, *(int **)((char *)obj + 0xB8));
    ObjMsg_AllocQueue(obj, 8);
    q = *(int **)((char *)obj + 0x64);
    if (q != NULL) {
        *(u32 *)((char *)q + 0x30) |= 0x4008;
    }
}

extern int *gModgfxInterface;
void DFP_Torch_free(int obj) {
    (*(void (**)(int))(*(int *)gModgfxInterface + 0x18))(obj);
    (*(void (**)(int))(*(int *)gExpgfxInterface + 0x18))(obj);
}

void dfpobjcreator_init(int obj, s8 *def) {
    int *state = *(int **)((char *)obj + 0xB8);
    *(s16 *)obj = (s16)((s32)def[0x1E] << 8);
    *(s16 *)((char *)state + 0xC) = *(s16 *)((char *)def + 0x18);
    *(s16 *)((char *)state + 0xE) = *(s16 *)((char *)def + 0x1C);
    *(s16 *)((char *)state + 0x10) = *(s16 *)((char *)state + 0xE);
    *(s16 *)((char *)state + 0x12) = (s16)(s32)def[0x1F];
    *(s16 *)((char *)state + 0x14) = (s16)((s32)(u8)def[0x20] << 1);
    *(s16 *)((char *)state + 0x16) = 100;
}

void dfplevelcontrol_setScale(int unused, u8 *out) {
    s16 i = 0;
    s16 *p = lbl_80329848;
    for (; i < 9; i += 3) {
        out[i] = p[0];
        out[(s16)(i + 1)] = p[1];
        out[(s16)(i + 2)] = p[2];
        p += 3;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802028C0(int obj, int p2)
{
  extern void ObjHits_EnableObject(int);
  extern void ObjHits_SetHitVolumeSlot(int, int, int, int);
  extern int *gPlayerInterface;
  extern int lbl_80329640[];
  extern f32 lbl_803E6350;
  extern f32 lbl_803E6354;
  extern f32 lbl_803E6358;
  int sub = *(int *)(obj + 0xb8);
  int sub_40c = *(int *)(sub + 0x40c);

  if ((s32)(s8)*(u8 *)(p2 + 0x27a) != 0) {
    *(u8 *)(p2 + 0x25f) = 1;
    *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & ~0x8);
    *(u8 *)(obj + 0x36) = 255;
    *(u8 *)(p2 + 0x34d) = 1;
    *(f32 *)(p2 + 0x2a0) = lbl_803E6350 + (f32)(u32)*(u8 *)(sub + 0x406) / lbl_803E6354;
    ObjHits_EnableObject(obj);
    *(int *)(sub_40c + 0x18) = 0;
    *(s16 *)(sub_40c + 0x1c) = -1;
  } else {
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
  }

  if ((s32)(s8)*(u8 *)(p2 + 0x346) != 0) {
    *(s16 *)(sub + 0x402) = 1;
    *(u8 *)(sub_40c + 0x34) = 1;
  }

  if ((*(int *)(p2 + 0x314) & 0x200) != 0) {
    *(int *)(p2 + 0x314) = *(int *)(p2 + 0x314) & ~0x200;
    *(u8 *)(sub_40c + 0x14) = (u8)(*(u8 *)(sub_40c + 0x14) | 0x4);
  }

  if (*(f32 *)(obj + 0x98) < lbl_803E6358) {
    *(u8 *)(sub_40c + 0x14) = (u8)(*(u8 *)(sub_40c + 0x14) | 0x2);
  }

  (**(void (**)(int, int, int, int, int *))((char *)(*gPlayerInterface) + 0x34))(obj, p2, 7, 0, lbl_80329640);
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int dbholecontrol1_SeqFn(int obj, int unused, int p3)
{
  extern u8 Obj_IsLoadingLocked(void);
  extern void *mapRomListFindItem(int, int, int, int, int);
  extern int Obj_AllocObjectSetup(int, int);
  extern void memcpy(int, void *, int);
  extern void loadObjectAtObject(int, int);
  extern int *ObjGroup_GetObjects(int, int *);
  extern void ObjGroup_RemoveObject(int, int);
  extern void ObjMsg_SendToObjects(int, int, int, int, int);
  extern int lbl_803DDCE0;
  int data = *(int *)(obj + 0x4c);
  int i;

  for (i = 0; i < *(u8 *)(p3 + 0x8b); i++) {
    void *res;
    int newObj;
    if (*(u8 *)(p3 + 0x81 + i) != 1) continue;
    if (GameBit_Get((s32)(s8)*(u8 *)(data + 0x19) + 2601) != 0) continue;
    if (Obj_IsLoadingLocked() == 0) continue;
    res = mapRomListFindItem(0x4658A, 0, 0, 0, 0);
    if (res == NULL) continue;
    newObj = Obj_AllocObjectSetup(56, 1337);
    memcpy(newObj, res, 56);
    *(f32 *)(newObj + 8) = *(f32 *)(obj + 0xc);
    *(f32 *)(newObj + 12) = *(f32 *)(obj + 0x10);
    *(f32 *)(newObj + 16) = *(f32 *)(obj + 0x14);
    *(int *)(newObj + 20) = -1;
    *(s16 *)(newObj + 26) = 149;
    loadObjectAtObject(obj, newObj);
  }

  if (GameBit_Get(*(s16 *)(data + 0x1e)) != 0 || lbl_803DDCE0 != 0) {
    int count;
    int *objs = ObjGroup_GetObjects(36, &count);
    ObjMsg_SendToObjects(0, 3, obj, 17, 0);
    while (count != 0) {
      ObjGroup_RemoveObject(*objs, 36);
      objs++;
      count--;
    }
    return 4;
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma peephole off
#pragma scheduling off
int dbstealerworm_func0B(int obj, u8 msg, int *out)
{
    int state = *(int *)(obj + 0xb8);
    int sub = *(int *)(state + 0x40c);
    int result = 0;
    u8 b;
    switch (msg) {
    case 0x80:
        break;
    case 0x81:
        b = *(u8 *)(state + 0x404);
        if ((b & 2) == 0) {
            break;
        }
        *(u8 *)(state + 0x404) = b & ~2;
        if (out != 0) {
            *out = 1;
        }
        result = 1;
        break;
    case 0x82:
        if (*(s16 *)(state + 0x274) != 0xb) {
            break;
        }
        if (out == 0) {
            break;
        }
        *(int *)(sub + 0x3c) = (int)out;
        result = 1;
        break;
    case 0x83:
        result = *(int *)(sub + 0x3c);
        break;
    }
    return result;
}
#pragma peephole reset
#pragma scheduling reset

extern int lbl_803AD0D8[];
extern int fn_802025C0();
extern int fn_80202428();
extern int fn_80201BD8(int obj, int p2, f32 t);
extern int fn_802017A4(int obj, int p2, f32 t);
extern int fn_80201358();
extern int fn_80200E44(int obj, int p2, f32 t);
extern int fn_80200A70(int obj, int p2, f32 t);
extern int fn_80200850();
extern int fn_80200750();
extern int fn_802004B0(int obj, int p2, f32 t);
extern int fn_80200088();
extern int fn_801FFE18();

#pragma peephole off
#pragma scheduling off
void DBstealerwo_setFuncPtrs_80203c78(void)
{
    lbl_803AD0F4[0] = (int)fn_802028C0;
    lbl_803AD0F4[1] = (int)fn_80202720;
    lbl_803AD0F4[2] = (int)fn_802025C0;
    lbl_803AD0F4[3] = (int)fn_80202524;
    lbl_803AD0F4[4] = (int)fn_80202428;
    lbl_803AD0F4[5] = (int)fn_80202294;
    lbl_803AD0F4[6] = (int)fn_802020B0;
    lbl_803AD0F4[7] = (int)fn_80201BD8;
    lbl_803AD0F4[8] = (int)fn_802017A4;
    lbl_803AD0F4[9] = (int)fn_802015EC;
    lbl_803AD0F4[10] = (int)fn_80201358;
    lbl_803AD0F4[11] = (int)fn_80200E44;
    lbl_803AD0F4[12] = (int)fn_80200A70;
    lbl_803AD0F4[13] = (int)fn_80200850;
    lbl_803AD0F4[14] = (int)fn_80200750;
    lbl_803AD0F4[15] = (int)fn_802004B0;
    lbl_803AD0D8[0] = (int)fn_80200460;
    lbl_803AD0D8[1] = (int)fn_80200410;
    lbl_803AD0D8[2] = (int)fn_80200380;
    lbl_803AD0D8[3] = (int)fn_8020032C;
    lbl_803AD0D8[4] = (int)fn_802002C4;
    lbl_803AD0D8[5] = (int)fn_80200088;
    lbl_803AD0D8[6] = (int)fn_801FFE18;
}
#pragma peephole reset
#pragma scheduling reset

extern void fn_80202EF0(int obj, int p2);
extern int *gPartfxInterface;

#pragma peephole off
#pragma scheduling off
#pragma dont_inline on
void fn_80203000(int obj, int param2)
{
    int i;
    int state = *(int *)(param2 + 0x40c);
    if ((*(u8 *)(state + 0x14) & 1) && *(void **)(param2 + 0x2d0) != 0) {
        fn_80202EF0(obj, param2);
    }
    if (*(u8 *)(state + 0x14) & 2) {
        (*(void (*)(int, int, int, int, int, int))(*(int *)(*gPartfxInterface + 0x8)))(obj, 0x345, 0, 2, -1, 0);
        (*(void (*)(int, int, int, int, int, int))(*(int *)(*gPartfxInterface + 0x8)))(obj, 0x345, 0, 2, -1, 0);
        (*(void (*)(int, int, int, int, int, int))(*(int *)(*gPartfxInterface + 0x8)))(obj, 0x345, 0, 2, -1, 0);
    }
    if (*(u8 *)(state + 0x14) & 4) {
        for (i = 0; i < 0xa; i++) {
            (*(void (*)(int, int, int, int, int, int))(*(int *)(*gPartfxInterface + 0x8)))(obj, 0x343, 0, 1, -1, 0);
        }
    }
    *(u8 *)(state + 0x14) = 0;
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

extern void unlockLevel(int a, int b, int c);
extern void Music_Trigger(int a, int b);
extern int *gMapEventInterface;

typedef struct DfpFlags7 {
    u8 b80 : 1;
    u8 b40 : 1;
    u8 b20 : 1;
    u8 rest : 5;
} DfpFlags7;

#pragma peephole off
#pragma scheduling off
void dfplevelcontrol_init(int obj, int param2)
{
    int state = *(int *)(obj + 0xb8);
    int v;
    ObjGroup_AddObject(obj, 9);
    ((DfpFlags7 *)(state + 7))->b80 = GameBit_Get(0xd5d);
    ((DfpFlags7 *)(state + 7))->b40 = GameBit_Get(0xd59);
    ((DfpFlags7 *)(state + 7))->b20 = GameBit_Get(0xd5a);
    *(void **)(obj + 0xbc) = dfplevelcontrol_SeqFn;
    *(s16 *)(state + 2) = 1;
    v = *(s16 *)(param2 + 0x1a);
    if (v != 0 && v <= 2) {
        *(s16 *)(state + 2) = v;
    }
    ((MapEventInterface *)*(int *)gMapEventInterface)->getMode(*(s8 *)(obj + 0xac));
    unlockLevel(0, 0, 1);
    *(u16 *)(obj + 0xb0) = *(u16 *)(obj + 0xb0) | 0x4000;
    if (*(s8 *)(obj + 0xac) == 0x15) {
        GameBit_Set(0xdce, 0);
    }
    if ((u32)GameBit_Get(0xdce) != 0) {
        Music_Trigger(0x37, 0);
        Music_Trigger(0xe4, 0);
    }
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E62F4;
extern f32 lbl_803E62A8;

#pragma peephole off
#pragma scheduling off
int fn_80202428(int obj, int param2)
{
    int state = *(int *)(obj + 0xb8);
    u32 v;
    int sub;
    if (*(s8 *)(param2 + 0x27a) != 0) {
        ObjHits_EnableObject(obj);
    }
    ObjHits_SetHitVolumeSlot(obj, 0xa, 1, -1);
    *(f32 *)(param2 + 0x2a0) = lbl_803E62F4;
    if (*(s8 *)(param2 + 0x27a) != 0) {
        ObjAnim_SetCurrentMove((void *)obj, 0xa, lbl_803E62A8, 0);
        *(u8 *)(param2 + 0x346) = 0;
    }
    *(u8 *)(param2 + 0x34d) = 1;
    sub = *(int *)(state + 0x40c);
    *(u8 *)(sub + 0x14) = *(u8 *)(sub + 0x14) | 0x2;
    v = *(u32 *)(param2 + 0x314);
    if (v & 1) {
        *(u32 *)(param2 + 0x314) = v & ~1;
        *(u8 *)(sub + 0x14) = *(u8 *)(sub + 0x14) | 0x1;
    }
    if (*(s8 *)(param2 + 0x346) != 0) {
        *(u8 *)(sub + 0x34) = 1;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E62E8;
extern f32 lbl_803E62EC;

#pragma peephole off
#pragma scheduling off
int fn_80200750(int obj, int param2)
{
    int sub = *(int *)(*(int *)(obj + 0xb8) + 0x40c);
    *(u8 *)(sub + 0x14) = *(u8 *)(sub + 0x14) | 0x2;
    *(u8 *)(sub + 0x15) = *(u8 *)(sub + 0x15) | 0x4;
    *(f32 *)(param2 + 0x2a0) = lbl_803E62E8;
    if (*(s8 *)(param2 + 0x27a) != 0) {
        ObjAnim_SetCurrentMove((void *)obj, 0x11, lbl_803E62A8, 0);
        *(u8 *)(param2 + 0x346) = 0;
    }
    *(u8 *)(param2 + 0x34d) = 0x1f;
    if (*(s8 *)(param2 + 0x27a) != 0) {
        *(int *)(sub + 0x18) = *(int *)(param2 + 0x2d0);
        *(s16 *)(sub + 0x1c) = 0x24;
        *(int *)(sub + 0x2c) = 0;
        ObjMsg_SendToObject(*(int *)(sub + 0x18), 0x11, obj, 0x12);
        Sfx_PlayFromObject(obj, SFXfoot_ice_run_3);
    }
    if (*(f32 *)(obj + 0x98) > lbl_803E62EC) {
        *(u8 *)(sub + 0x34) = 1;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern int Resource_Acquire(int id, int flag);
extern f64 lbl_803E63F0;
extern f32 lbl_803E63E4;
extern f32 lbl_803E63E8;
extern f32 lbl_803E63E0;

#pragma peephole off
#pragma scheduling off
void DFP_Torch_init(int obj, int param2)
{
    int state = *(int *)(obj + 0xb8);
    int res;
    f32 local_18;
    int v;
    *(s16 *)obj = (s16)((*(s8 *)(param2 + 0x18) & 0x3f) << 10);
    v = *(s16 *)(param2 + 0x1a);
    if (v > 0) {
        *(f32 *)(obj + 8) = (f32)v / lbl_803E63E4;
    } else {
        *(f32 *)(obj + 8) = lbl_803E63E8;
    }
    *(u8 *)(state + 9) = *(u8 *)(param2 + 0x19);
    *(int *)(state) = *(s16 *)(param2 + 0x1e);
    local_18 = lbl_803E63E0;
    if (*(u8 *)(state + 9) == 0) {
        *(u8 *)(state + 0xa) = 1;
        res = Resource_Acquire(0x69, 1);
        if (*(s16 *)(param2 + 0x1c) == 0) {
            (*(void (*)(int, int, void *, int, int, int))(*(int *)(*(int *)res + 4)))(obj, 0, &local_18, 0x10004, -1, 0);
        }
    }
    *(u8 *)(state + 0xd) = (u8)*(s16 *)(param2 + 0x1c);
    *(u16 *)(obj + 0xb0) = *(u16 *)(obj + 0xb0) | 0x2000;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80202EF0(int obj, int p2)
{
    extern u8 Obj_IsLoadingLocked(void);
    extern u8 *Obj_AllocObjectSetup(int, int);
    extern u8 *Obj_SetupObject(u8 *, int, int, int, int);
    extern f32 lbl_803E637C;
    extern f32 lbl_803E62B4;
    extern f32 lbl_803E62B8;
    extern f32 lbl_803E6380;
    u8 *setup;
    u8 *newObj;
    f32 dur;
    f32 t;

    if (Obj_IsLoadingLocked() != 0) {
        setup = Obj_AllocObjectSetup(0x24, 0x30a);
        *(f32 *)(setup + 8) = *(f32 *)(obj + 0xc);
                *(f32 *)(setup + 0xc) = lbl_803E637C + *(f32 *)(obj + 0x10);
                *(f32 *)(setup + 0x10) = *(f32 *)(obj + 0x14);
                setup[4] = 1;
                setup[5] = 1;
                setup[6] = 0xff;
                setup[7] = 0xff;
        newObj = Obj_SetupObject(setup, 5, *(s8 *)(obj + 0xac), -1, 0);
        if (newObj != NULL) {
            t = *(f32 *)(p2 + 0x2c0) / lbl_803E62B4;
            dur = lbl_803E62B8 * t;
            *(f32 *)(newObj + 0x24) = (*(f32 *)(*(int *)(p2 + 0x2d0) + 0xc) - *(f32 *)(obj + 0xc)) / dur;
            *(f32 *)(newObj + 0x28) = ((lbl_803E6380 * t + *(f32 *)(*(int *)(p2 + 0x2d0) + 0x10)) - *(f32 *)(obj + 0x10)) / dur;
            *(f32 *)(newObj + 0x2c) = (*(f32 *)(*(int *)(p2 + 0x2d0) + 0x14) - *(f32 *)(obj + 0x14)) / dur;
            *(int *)(newObj + 0xc4) = obj;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
#pragma dont_inline on
int fn_80202C78(int obj, int p6, f32 p1, f32 p2, f32 p3, f32 p4)
{
    extern int Obj_GetYawDeltaToObject(int, int, f32 *);
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E6370;
    extern f32 timeDelta;
    extern f32 lbl_803E634C;
    extern f32 lbl_803E62C8;
    extern f32 lbl_803E6374;
    int state = *(int *)(obj + 0xb8);
    f32 yawF;
    int yaw;
    f32 zero;
    f32 a;
    f32 ratio;
    f32 k;
    f32 cur;
    f32 prod;

    yaw = Obj_GetYawDeltaToObject(obj, p6, &yawF);
    zero = lbl_803E62A8;
    if (zero == p4) {
        return 0;
    }
    yawF -= p1;
    ratio = yawF / p4;
    yawF = ratio;
    if (ratio >= zero) {
        a = ratio;
    } else {
        a = -ratio;
    }
    if (a < lbl_803E6370) {
        return 1;
    }
    if (ratio < lbl_803E62A8) {
        p2 = -p2;
    }
    cur = *(f32 *)(state + 0x280);
    k = timeDelta * lbl_803E634C;
    prod = p2 * (lbl_803E62C8 - (f32)(s16)yaw / lbl_803E6374);
    *(f32 *)(state + 0x280) = k * (prod - cur) + cur;
    *(f32 *)(state + 0x284) = lbl_803E62A8;
    return 0;
}
#pragma dont_inline reset
#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma dont_inline on
int fn_80202DA4(u8 *obj, u8 *p6, f32 p1, f32 p2, f32 p3, f32 p4)
{
    extern int Obj_GetYawDeltaToObject(u8 *, u8 *, f32 *);
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E6378;
    extern f32 timeDelta;
    extern f32 lbl_803E634C;
    extern f32 lbl_803E62C8;
    extern f32 lbl_803E6374;
    int state = *(int *)(obj + 0xb8);
    f32 yawF;
    int yaw;
    f32 dy;
    f32 zero;
    f32 k;
    f32 cur;
    f32 prod;

    if (obj == NULL || p6 == NULL) {
        return 0;
    }
    yaw = Obj_GetYawDeltaToObject(obj, p6, &yawF);
    zero = lbl_803E62A8;
    if (zero == p4) {
        return 0;
    }
    if (yawF < p1) {
        dy = *(f32 *)(obj + 0x10) - *(f32 *)(p6 + 0x10);
        dy = (dy >= zero) ? dy : -dy;
        if (dy < lbl_803E6378) {
            return 1;
        }
    }
    cur = *(f32 *)(state + 0x280);
    k = timeDelta * lbl_803E634C;
    prod = p2 * (lbl_803E62C8 - (f32)(s16)yaw / lbl_803E6374);
    *(f32 *)(state + 0x280) = k * (prod - cur) + cur;
    *(f32 *)(state + 0x284) = lbl_803E62A8;
    return 0;
}
#pragma scheduling reset

#pragma scheduling off
void dfpobjcreator_update(int obj)
{
    extern u8 Obj_IsLoadingLocked(void);
    extern uint GameBit_Get(int);
    extern u8 *Obj_AllocObjectSetup(int, int);
    extern u8 *Obj_SetupObject(u8 *, int, int, int, int);
    extern f32 timeDelta;
    int data = *(int *)(obj + 0x4c);
    int state = *(int *)(obj + 0xb8);
    u8 *setup;
    u8 *newObj;

    if (Obj_IsLoadingLocked() != 0) {
        switch (*(s16 *)(data + 0x1a)) {
        case 7:
            *(s16 *)(state + 0x10) -= (int)timeDelta;
            if (*(s16 *)(state + 0x10) <= 0 && GameBit_Get(*(s16 *)(state + 0xc)) != 0) {
                *(s16 *)(state + 0x10) = *(s16 *)(state + 0xe);
                setup = Obj_AllocObjectSetup(0x24, 0x71b);
                *(f32 *)(setup + 0x8) = *(f32 *)(data + 0x8);
                *(f32 *)(setup + 0xc) = *(f32 *)(data + 0xc);
                *(f32 *)(setup + 0x10) = *(f32 *)(data + 0x10);
                setup[4] = *(u8 *)(data + 4);
                setup[5] = *(u8 *)(data + 5);
                setup[6] = *(u8 *)(data + 6);
                setup[7] = *(u8 *)(data + 7);
                *(s16 *)(setup + 0x1e) = -1;
                *(s16 *)(setup + 0x20) = -1;
                *(s16 *)(setup + 0x1a) = 0xdc;
                newObj = Obj_SetupObject(setup, 5, *(s8 *)(obj + 0xac), -1, *(int *)(obj + 0x30));
                *(int *)(newObj + 0xf4) = *(s8 *)(data + 0x1e);
            }
            break;
        }
    }
}
#pragma dont_inline reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802025C0(int obj, int p2)
{
    extern void ObjHits_EnableObject(int);
    extern void ObjHits_SetHitVolumeSlot(int, int, int, int);
    extern void ObjAnim_SetCurrentMove(int obj, int n, f32 v, int m);
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E6344;
    extern f32 lbl_803E6348;
    int state = *(int *)(obj + 0xb8);
    int sub = *(int *)(state + 0x40c);

    if (*(s8 *)(p2 + 0x27a) != 0) {
        ObjHits_EnableObject(obj);
    }
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
    if (*(s8 *)(p2 + 0x27a) != 0) {
        if ((int)randomGetRange(0, 1) != 0) {
            if (*(s8 *)(p2 + 0x27a) != 0) {
                ObjAnim_SetCurrentMove(obj, 6, lbl_803E62A8, 0);
                *(u8 *)(p2 + 0x346) = 0;
            }
        } else {
            if (*(s8 *)(p2 + 0x27a) != 0) {
                ObjAnim_SetCurrentMove(obj, 7, lbl_803E62A8, 0);
                *(u8 *)(p2 + 0x346) = 0;
            }
        }
        *(u8 *)(p2 + 0x34d) = 1;
        *(f32 *)(p2 + 0x2a0) = lbl_803E6344 + (f32)*(u8 *)(state + 0x406) / lbl_803E6348;
    }
    *(f32 *)(p2 + 0x280) = lbl_803E62A8;
    if (*(s8 *)(p2 + 0x346) != 0) {
        *(u8 *)(sub + 0x34) = 1;
    }
    *(u8 *)(sub + 0x14) |= 2;
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void dbstealerworm_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    extern void fn_8003B5E0(int, int, int, int);
    extern void objParticleFn_80099d84(int, f32, int, f32, int);
    extern void ObjPath_GetPointWorldPosition(int, int, char *, char *, char *, int);
    extern f32 lbl_803E62D0;
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E62C8;
    int sub;
    int state;
    char *path;

    state = *(int *)(obj + 0xb8);
    sub = *(int *)(state + 0x40c);
    if (*(void **)(sub + 0x18) != NULL) {
        *(f32 *)(*(int *)(sub + 0x18) + 0xc) = *(f32 *)(obj + 0xc);
        *(f32 *)(*(int *)(sub + 0x18) + 0x10) = *(f32 *)(obj + 0x10);
        *(f32 *)(*(int *)(sub + 0x18) + 0x14) = *(f32 *)(obj + 0x14);
        *(f32 *)(*(int *)(sub + 0x18) + 0x10) += lbl_803E62D0;
    }
    if (visible != 0 && *(int *)(obj + 0xf4) == 0 && *(s16 *)(state + 0x402) != 0) {
        {
            if (*(f32 *)(state + 0x3e8) != lbl_803E62A8) {
                fn_8003B5E0(0xc8, 0, 0, (int)*(f32 *)(state + 0x3e8));
            }
            ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E62C8);
            if ((*(u16 *)(state + 0x400) & 0x60) != 0) {
                objParticleFn_80099d84(obj, lbl_803E62C8, 3, *(f32 *)(state + 0x3e8), 0);
            }
            path = *(char **)(sub + 0x18);
            if (path != NULL && *(void **)(path + 0x50) != NULL) {
                ObjPath_GetPointWorldPosition(obj, 3, path + 0xc, path + 0x10, path + 0x14, 0);
                ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(*(int *)(sub + 0x18), p2, p3, p4, p5, lbl_803E62C8);
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80200850(int obj, int p2)
{
    extern void ObjAnim_SetCurrentMove(int obj, int n, f32 v, int m);
    extern int Stack_IsFull(int sp);
    extern void Stack_Push(int sp, int *args);
    extern f32 sqrtf(f32 x);
    extern f32 lbl_803E62F0;
    extern f32 lbl_803E62F4;
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E62EC;
    extern f32 lbl_803E62F8;
    extern f32 lbl_803E62FC;
    extern f32 lbl_803E62B8;
    int sub = *(int *)(*(int *)(obj + 0xb8) + 0x40c);
    int q;
    int tmp;
    f32 v;
    f32 d;
    struct {
        int msgE[3];
        int msg7[3];
        int msg9[3];
        f32 pos[3];
    } stk;

    *(u8 *)(sub + 0x14) |= 2;
    *(u8 *)(sub + 0x15) &= ~4;
    v = *(f32 *)(p2 + 0x280);
    d = lbl_803E62F0;
    *(f32 *)(p2 + 0x280) = v / d;
    *(f32 *)(p2 + 0x284) = *(f32 *)(p2 + 0x284) / d;
    *(f32 *)(p2 + 0x2a0) = lbl_803E62F4;
    if (*(s8 *)(p2 + 0x27a) != 0) {
        ObjAnim_SetCurrentMove(obj, 0x11, lbl_803E62A8, 0);
        *(u8 *)(p2 + 0x346) = 0;
    }
    *(u8 *)(p2 + 0x34d) = 0x1f;
    if (*(f32 *)(obj + 0x98) > lbl_803E62EC
        && *(f32 *)(*(int *)(p2 + 0x2d0) + 0x10) - lbl_803E62F8 <= *(f32 *)(obj + 0x10)) {
        q = *(int *)(sub + 0x24);
        stk.msg9[0] = 9;
        stk.msg9[1] = 0;
        stk.msg9[2] = 0x24;
        if (Stack_IsFull(q) == 0) {
            Stack_Push(q, stk.msg9);
        }
        *(u8 *)(sub + 0x34) = 1;
        tmp = *(int *)(p2 + 0x2d0);
        q = *(int *)(sub + 0x24);
        stk.msg7[0] = 7;
        stk.msg7[1] = 1;
        stk.msg7[2] = tmp;
        if (Stack_IsFull(q) == 0) {
            Stack_Push(q, stk.msg7);
        }
        *(u8 *)(sub + 0x34) = 1;
    } else {
        stk.pos[0] = *(f32 *)(obj + 0xc);
        stk.pos[1] = *(f32 *)(obj + 0x10);
        stk.pos[2] = *(f32 *)(obj + 0x14);
        stk.pos[1] = stk.pos[1] + lbl_803E62FC;
        stk.pos[0] = *(f32 *)(*(int *)(p2 + 0x2d0) + 0xc) - stk.pos[0];
        stk.pos[1] = *(f32 *)(*(int *)(p2 + 0x2d0) + 0x10) - stk.pos[1];
        stk.pos[2] = *(f32 *)(*(int *)(p2 + 0x2d0) + 0x14) - stk.pos[2];
        if (sqrtf(stk.pos[2] * stk.pos[2] + (stk.pos[0] * stk.pos[0] + stk.pos[1] * stk.pos[1])) < lbl_803E62B8) {
            tmp = *(int *)(p2 + 0x2d0);
            q = *(int *)(sub + 0x24);
            stk.msgE[0] = 0xe;
            stk.msgE[1] = 1;
            stk.msgE[2] = tmp;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, stk.msgE);
            }
            *(u8 *)(sub + 0x34) = 1;
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

typedef struct {
    u8 flag80 : 1;
    u8 flag40 : 1;
    u8 flag20 : 1;
    u8 flag10 : 1;
} AnimFlags44;

#pragma scheduling off
#pragma peephole off
int fn_80200088(int obj, int p2)
{
    extern int Stack_IsEmpty(int);
    extern void Stack_Pop(int, int *);
    extern int ObjGroup_FindNearestObjectForObject(int, int, f32 *);
    extern int *gPlayerInterface;
    extern int lbl_803296FC[];
    extern f32 lbl_803E62AC;
    extern f32 lbl_803E62B0;
    extern f32 lbl_803E62B4;
    extern f32 lbl_803E62B8;
    int tmp = *(int *)(obj + 0xb8);
    int sub;
    int data = *(int *)(obj + 0x4c);
    int base;
    int n;
    u32 found;
    int i;
    int *p;
    u32 o;
    int buf[3];
    f32 range;

    range = lbl_803E62AC;
    sub = *(int *)(tmp + 0x40c);
    if (*(s8 *)(p2 + 0x27b) != 0 || ((u32)*(u8 *)(sub + 0x44) >> 6 & 1) != 0) {
        *(u8 *)(sub + 0x15) &= ~4;
        ((AnimFlags44 *)(sub + 0x44))->flag40 = 0;
        if (Stack_IsEmpty(*(int *)(sub + 0x24)) == 0) {
            Stack_Pop(*(int *)(sub + 0x24), buf);
        }
        base = *(int *)(sub + 0x0);
        n = (*(int *)(sub + 0x20) - *(int *)base) / 12;
        if (n >= *(s16 *)(base + 4)) {
            *(int *)(sub + 0x20) = 0;
        }
        if (*(void **)(sub + 0x20) == NULL) {
            *(int *)(sub + 0x20) = *(int *)*(int *)(sub + 0x0);
            *(f32 *)(obj + 0xc) = *(f32 *)(data + 0x8);
            *(f32 *)(obj + 0x10) = *(f32 *)(data + 0xc);
            *(f32 *)(obj + 0x14) = *(f32 *)(data + 0x10);
        }
        if (*(int *)(*(int *)(sub + 0x20) + 4) != 0) {
            *(int *)(p2 + 0x2d0) = ObjGroup_FindNearestObjectForObject(*(int *)(*(int *)(sub + 0x20) + 4), obj, &range);
        }
        if (*(void **)(p2 + 0x2d0) != NULL) {
            (**(void (**)(int, int, int))((char *)(*gPlayerInterface) + 0x14))(obj, p2, *(int *)*(int *)(sub + 0x20));
        }
        return 0;
    } else {
        f32 t;
        if (*(void **)(sub + 0x18) == NULL && (t = *(f32 *)(sub + 0x38)) > lbl_803E62B0) {
            *(f32 *)(sub + 0x38) = t - lbl_803E62B0;
            range = lbl_803E62B4;
            i = 3;
            found = 0;
            p = &lbl_803296FC[3];
            for (; p--, --i >= 0;) {
                o = ObjGroup_FindNearestObjectForObject(*p, obj, &range);
                if (o != 0) {
                    found = o;
                }
            }
            *(int *)(p2 + 0x2d0) = found;
            if (found != 0) {
                if (range < lbl_803E62B8) {
                    (**(void (**)(int, int, int))((char *)(*gPlayerInterface) + 0x14))(obj, p2, 2);
                } else {
                    (**(void (**)(int, int, int))((char *)(*gPlayerInterface) + 0x14))(obj, p2, 4);
                }
            }
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80203144(int obj, int p2, int p3)
{
    extern int ObjGroup_FindNearestObject(int, int, f32 *);
    extern void ObjGroup_AddObject(int, int);
    extern void *Obj_GetPlayerObject(void);
    extern void Sfx_PlayFromObject(int, u16);
    extern f32 sqrtf(f32 x);
    extern u32 randomGetRange(int min, int max);
    extern void **gBaddieControlInterface;
    extern int lbl_80329640[];
    extern f32 lbl_803E62B0;
    extern f32 lbl_803E6354;
    extern f32 lbl_803E6384;
    extern f32 timeDelta;
    int sub = *(int *)(p2 + 0x40c);
    u32 near;
    int data;
    char *player;
    f32 dist;
    struct {
        f32 range;
        f32 d[3];
    } stk;

    stk.range = lbl_803E62B0;
    data = *(int *)(obj + 0x4c);
    near = (**(u32 (**)(int, int, f32, int))((char *)*gBaddieControlInterface + 0x48))(obj, p3, (f32)*(u16 *)(p2 + 0x3fe), 0x8000);
    if (near == 0 && (*(u8 *)(p2 + 0x404) & 0x10) != 0) {
        near = ObjGroup_FindNearestObject(0x24, obj, &stk.range);
    }
    if (near == 0 && (*(u8 *)(p2 + 0x404) & 0x10) != 0 && (*(u8 *)(p2 + 0x404) & 2) == 0 && (*(u8 *)(data + 0x2b) & 2) != 0) {
        near = ObjGroup_FindNearestObject(0x24, obj, 0);
    }
    if (near != 0 && (*(u8 *)(p2 + 0x404) & 2) == 0) {
        (**(void (**)(int, int, int, int, int, int, int, int, int))((char *)*gBaddieControlInterface + 0x28))(obj, p3, p2 + 0x35c, *(s16 *)(p2 + 0x3f4), 0, 0, 0, 8, -1);
        *(int *)(p3 + 0x2d0) = near;
        *(u8 *)(p3 + 0x349) = 0;
        ObjGroup_AddObject(obj, 3);
        *(u16 *)(p2 + 0x402) = 1;
    } else {
        player = Obj_GetPlayerObject();
        if (player != NULL) {
            stk.d[0] = *(f32 *)(player + 0x18) - *(f32 *)(obj + 0x18);
            stk.d[1] = *(f32 *)(player + 0x1c) - *(f32 *)(obj + 0x1c);
            stk.d[2] = *(f32 *)(player + 0x20) - *(f32 *)(obj + 0x20);
            dist = sqrtf(stk.d[2] * stk.d[2] + (stk.d[0] * stk.d[0] + stk.d[1] * stk.d[1]));
        } else {
            dist = lbl_803E6354;
        }
        if (*(f32 *)(sub + 0xc) > *(f32 *)(sub + 0x10) && dist < lbl_803E6384) {
            Sfx_PlayFromObject(obj, (u16)lbl_80329640[1]);
            *(f32 *)(sub + 0x10) = *(f32 *)(sub + 0x10) + (f32)(int)randomGetRange(0x32, 0xfa);
        }
        *(f32 *)(sub + 0xc) += timeDelta;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
void dfplevelcontrol_update(int obj)
{
    extern void *Obj_GetPlayerObject(void);
    extern uint GameBit_Get(int);
    extern void GameBit_Set(int, int);
    extern void Sfx_PlayFromObject(int, u16);
    extern void coordsToMapCell(f32, f32);
    extern void fn_80204098(int);
    extern void SCGameBitLatch_Update(void *, int, int, int, int, int);
    extern void SCGameBitLatch_UpdateInverted(void *, int, int, int, int, int);
    extern s16 lbl_803DC180;
    extern f32 timeDelta;
    int state = *(int *)(obj + 0xb8);
    char *player;
    u8 b1;
    u8 b2;
    u8 b3;
    int mode;

    player = Obj_GetPlayerObject();
    b1 = GameBit_Get(0xd5d);
    b2 = GameBit_Get(0xd59);
    b3 = GameBit_Get(0xd5a);
    if ((b1 != 0 && ((u32)*(u8 *)(state + 7) >> 7 & 1) == 0)
        || (b2 != 0 && ((u32)*(u8 *)(state + 7) >> 6 & 1) == 0)
        || (b3 != 0 && ((u32)*(u8 *)(state + 7) >> 5 & 1) == 0)) {
        Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
    }
    ((DfpFlags7 *)(state + 7))->b80 = b1;
    ((DfpFlags7 *)(state + 7))->b40 = b2;
    ((DfpFlags7 *)(state + 7))->b20 = b3;
    if (GameBit_Get(0x5e8) == 0 && GameBit_Get(0x5ee) != 0 && GameBit_Get(0x5ef) != 0) {
        GameBit_Set(0x5e8, 1);
    }
    coordsToMapCell(*(f32 *)(player + 0xc), *(f32 *)(player + 0x14));
    mode = (u8)(**(int (**)(int))((char *)*(int *)gMapEventInterface + 0x40))(*(s8 *)(obj + 0xac));
    switch (mode) {
    case 1:
        if (lbl_803DC180 != 0) {
            lbl_803DC180 -= (int)timeDelta;
            if (lbl_803DC180 <= 0) {
                lbl_803DC180 = 0;
            }
        }
        fn_80204320(obj);
        break;
    case 2:
        fn_80204098(obj);
        break;
    case 4:
        break;
    case 0:
        break;
    }
    SCGameBitLatch_Update((void *)(state + 8), 2, -1, -1, 0xdce, 0x95);
    SCGameBitLatch_UpdateInverted((void *)(state + 8), 4, -1, -1, 0xdce, 0x37);
    SCGameBitLatch_UpdateInverted((void *)(state + 8), 1, -1, -1, 0xdce, 0xe4);
    GameBit_Set(0xdcf, 0);
}
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80202A2C(int obj, int *objs, f32 *weights, int n, f32 limit)
{
    extern int ObjGroup_FindNearestObjectForObject(int, int, f32 *);
    extern f32 fn_80293E80(f32);
    extern f32 sin(f32);
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E635C;
    extern f32 lbl_803E62C8;
    extern f32 lbl_803E6360;
    extern f32 lbl_803E6364;
    int *po;
    f32 *pw;
    int state = *(int *)(obj + 0xb8);
    int i;
    f32 rangeInit;
    f32 accX;
    f32 accZ;
    u32 o;
    f32 k;
    f32 scale;
    f32 cosv;
    f32 sinv;
    f32 neg;
    f32 v;
    struct {
        f32 range;
        f32 d[3];
    } stk;

    accX = lbl_803E62A8;
    accZ = lbl_803E62A8;
    i = 0;
    po = objs;
    pw = weights;
    rangeInit = lbl_803E635C;
    for (; i < n; i++) {
        stk.range = rangeInit;
        o = ObjGroup_FindNearestObjectForObject(*po, obj, &stk.range);
        if (o != 0) {
            if (stk.range == lbl_803E62A8) {
                return 0;
            }
            k = lbl_803E62C8 - stk.range / lbl_803E635C;
            k = k * k;
            k = k * k;
            stk.d[0] = *(f32 *)(o + 0xc) - *(f32 *)(obj + 0xc);
            stk.d[1] = *(f32 *)(o + 0x10) - *(f32 *)(obj + 0x10);
            stk.d[2] = *(f32 *)(o + 0x14) - *(f32 *)(obj + 0x14);
            scale = lbl_803E62C8 / stk.range;
            stk.d[0] *= scale;
            stk.d[1] *= scale;
            stk.d[2] *= scale;
            accX = accX - limit * (stk.d[0] * k * *pw);
            accZ = accZ - limit * (stk.d[2] * k * *pw);
        }
        po++;
        pw++;
    }
    cosv = fn_80293E80(lbl_803E6360 * (f32)*(s16 *)(obj + 0) / lbl_803E6364);
    sinv = sin(lbl_803E6360 * (f32)*(s16 *)(obj + 0) / lbl_803E6364);
    *(f32 *)(state + 0x284) = *(f32 *)(state + 0x284) + (accX * sinv - accZ * cosv);
    *(f32 *)(state + 0x280) = *(f32 *)(state + 0x280) + (-accZ * sinv - accX * cosv);
    v = *(f32 *)(state + 0x280);
    neg = -limit;
    if (v < neg) {
        v = neg;
    } else if (v > limit) {
        v = limit;
    }
    *(f32 *)(state + 0x280) = v;
    v = *(f32 *)(state + 0x284);
    *(f32 *)(state + 0x284) = (v < neg) ? neg : (v > limit) ? limit : v;
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void DFP_Torch_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    extern char *Camera_GetCurrentViewSlot(void);
    extern void voxmaps_worldToGrid(f32 *, s16 *);
    extern int voxmaps_traceLine(s16 *, s16 *, void *, int, int);
    extern f32 sqrtf(f32 x);
    extern u32 randomGetRange(int min, int max);
    extern f32 lbl_803E63C8;
    extern f32 lbl_803E63CC;
    extern f32 lbl_803E63D0;
    extern f32 lbl_803E63D4;
    extern f32 lbl_803E63D8;
    extern f32 lbl_803E63DC;
    extern f32 timeDelta;
    int state = *(int *)(obj + 0xb8);
    char *cam;
    f32 dist;
    f32 scale;
    struct {
        u8 pad[12];
        f32 col[3];
    } fx;
    struct {
        s32 out[2];
        s16 g2[4];
        s16 g1[4];
        f32 b[3];
        f32 a[3];
        f32 d[3];
    } stk2;

    if (visible == 0) {
        *(s16 *)(state + 4) = 0;
        *(u8 *)(state + 8) = 0;
    } else {
        objRenderFn_8003b8f4(lbl_803E63C8);
        if (*(u8 *)(state + 0xa) != 0) {
            *(u8 *)(state + 8) = 1;
            cam = Camera_GetCurrentViewSlot();
            stk2.d[0] = *(f32 *)(cam + 0xc) - *(f32 *)(obj + 0xc);
            stk2.d[1] = *(f32 *)(cam + 0x10) - *(f32 *)(obj + 0x10);
            stk2.d[2] = *(f32 *)(cam + 0x14) - *(f32 *)(obj + 0x14);
            dist = sqrtf(stk2.d[2] * stk2.d[2] + (stk2.d[0] * stk2.d[0] + stk2.d[1] * stk2.d[1]));
            if (dist > lbl_803E63CC) {
                scale = lbl_803E63C8 / dist;
                stk2.d[0] *= scale;
                stk2.d[1] *= scale;
                stk2.d[2] *= scale;
                stk2.a[0] = lbl_803E63D0 * stk2.d[0];
                stk2.a[1] = lbl_803E63D0 * stk2.d[1];
                stk2.a[2] = lbl_803E63D0 * stk2.d[2];
                stk2.a[0] = stk2.a[0] + *(f32 *)(obj + 0xc);
                stk2.a[1] = stk2.a[1] + *(f32 *)(obj + 0x10);
                stk2.a[2] = stk2.a[2] + *(f32 *)(obj + 0x14);
                stk2.b[0] = lbl_803E63D4 * stk2.d[0];
                stk2.b[1] = lbl_803E63D4 * stk2.d[1];
                stk2.b[2] = lbl_803E63D4 * stk2.d[2];
                stk2.b[0] = stk2.b[0] + *(f32 *)(cam + 0xc);
                stk2.b[1] = stk2.b[1] + *(f32 *)(cam + 0x10);
                stk2.b[2] = stk2.b[2] + *(f32 *)(cam + 0x14);
                voxmaps_worldToGrid(stk2.a, stk2.g1);
                voxmaps_worldToGrid(stk2.b, stk2.g2);
                if (voxmaps_traceLine(stk2.g1, stk2.g2, stk2.out, 0, 0) == 0) {
                    *(u8 *)(state + 8) = 0;
                    (*(void (*)(int))(*(int *)(*gExpgfxInterface + 0x14)))(obj);
                }
            }
            if (*(s16 *)(state + 4) > 0) {
                *(s16 *)(state + 4) -= (int)timeDelta;
            } else {
                if (*(u8 *)(state + 8) != 0) {
                    fx.col[0] = lbl_803E63D8;
                    fx.col[1] = lbl_803E63DC;
                    fx.col[2] = lbl_803E63D8;
                    (*(void (*)(int, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 0x8)))(obj, 0x1f7, &fx, 0x12, -1, 0);
                }
                *(s16 *)(state + 4) = (s16)(randomGetRange(-10, 10) + 0x3c);
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80204098(int obj)
{
    extern void *Obj_GetPlayerObject(void);
    extern uint GameBit_Get(int);
    extern void GameBit_Set(int, int);
    extern void Sfx_PlayFromObject(int, u16);
    extern void ObjMsg_SendToObject(void *, int, int, int);
    extern u8 lbl_803DC183;
    extern s16 lbl_80329848[];
    int state = *(int *)(obj + 0xb8);
    void *player;
    s16 i;
    s16 *p;

    player = Obj_GetPlayerObject();
    if (lbl_803DC183 != 0) {
        GameBit_Set(0x2d, 1);
        GameBit_Set(0x1d7, 1);
        for (i = 0, p = lbl_80329848; i < 9; i++) {
            *p = (s16)randomGetRange(1, 4);
            p++;
        }
        GameBit_Set(0x5e4, 0);
        *(s16 *)(state + 0) = 0;
        lbl_803DC183 = 0;
    }
    if (GameBit_Get(0x5e3) == 0 && GameBit_Get(0x5e0) != 0 && GameBit_Get(0x5e1) != 0) {
        Sfx_PlayFromObject(obj, SFXmn_spithit6);
        GameBit_Set(0x5e3, 1);
    }
    if (GameBit_Get(0x792) == 0 && GameBit_Get(0xb8c) != 0 && GameBit_Get(0xb8c) != 0) {
        Sfx_PlayFromObject(obj, SFXmn_spithit6);
        GameBit_Set(0x792, 1);
    }
    if (GameBit_Get(0xe58) == 0) {
        if (GameBit_Get(0x635) != 0 && *(u8 *)(state + 6) == 0) {
            Sfx_PlayFromObject(0, SFXfoot_wood_run_2);
            for (i = 0, p = lbl_80329848; i < 9; i++) {
                *p = (s16)randomGetRange(1, 4);
                p++;
            }
            GameBit_Set(0x5e4, 1);
            *(u8 *)(state + 6) = 1;
        } else {
            if (GameBit_Get(0x635) == 0 && *(u8 *)(state + 6) == 1) {
                *(u8 *)(state + 6) = 0;
                GameBit_Set(0x5e4, 0);
            }
        }
        if (GameBit_Get(0x5e5) != 0) {
            *(s16 *)(state + 0) = 300;
            ObjMsg_SendToObject(player, 0x60005, obj, 0);
        }
    }
    if (GameBit_Get(0x7a1) != 0) {
        if ((u8)(**(int (**)(int, int))((char *)*(int *)gMapEventInterface + 0x4c))(*(s8 *)(obj + 0xac), 6) == 0) {
            (**(void (**)(int, int, int))((char *)*(int *)gMapEventInterface + 0x50))(*(s8 *)(obj + 0xac), 6, 1);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_801FFE18(int obj, int p2)
{
    extern int Stack_IsEmpty(int);
    extern void Stack_Pop(int, int *);
    extern void Stack_Push(int, int *);
    extern void Obj_FreeObject(int);
    extern int ObjGroup_FindNearestObjectForObject(int, int, f32 *);
    extern int ObjGroup_ContainsObject(int, int);
    extern int *gPlayerInterface;
    extern u8 lbl_80329514[];
    extern f32 lbl_803E62AC;
    extern f32 lbl_803E62A8;
    int tmp = *(int *)(obj + 0xb8);
    int sub;
    int data = *(int *)(obj + 0x4c);
    int off;
    int n;
    char *entry;
    char *ptr;
    f32 range;

    range = lbl_803E62AC;
    sub = *(int *)(tmp + 0x40c);
    if (*(s8 *)(p2 + 0x27b) != 0 || *(u8 *)(sub + 0x34) != 0) {
        *(u8 *)(sub + 0x15) &= ~4;
        *(u8 *)(sub + 0x34) = 0;
        if (Stack_IsEmpty(*(int *)(sub + 0x24)) == 0) {
            Stack_Pop(*(int *)(sub + 0x24), (int *)(sub + 0x28));
        } else {
            if (*(u32 *)(data + 0x14) == 0xFFFFFFFF) {
                Obj_FreeObject(obj);
                return 0;
            }
            entry = (char *)&lbl_80329514[*(s16 *)(data + 0x24) * 8];
            n = *(s16 *)(entry + 4);
            off = n * 12;
            for (; n != 0; n--) {
                Stack_Push(*(int *)(sub + 0x24), (int *)(*(int *)entry + (off -= 12)));
            }
            *(u8 *)(sub + 0x34) = 1;
            *(f32 *)(obj + 0xc) = *(f32 *)(data + 0x8);
            *(f32 *)(obj + 0x10) = *(f32 *)(data + 0xc);
            *(f32 *)(obj + 0x14) = *(f32 *)(data + 0x10);
        }
        switch (*(int *)(sub + 0x2c)) {
        case 0:
            if (*(int *)(sub + 0x30) != 0) {
                *(int *)(p2 + 0x2d0) = ObjGroup_FindNearestObjectForObject(*(int *)(sub + 0x30), obj, &range);
            }
            break;
        case 1:
            *(int *)(p2 + 0x2d0) = *(int *)(sub + 0x30);
            break;
        }
        if (*(void **)(p2 + 0x2d0) != NULL) {
            (**(void (**)(int, int, int))((char *)(*gPlayerInterface) + 0x14))(obj, p2, *(int *)(sub + 0x28));
        }
        return 0;
    } else {
        switch (*(int *)(sub + 0x2c)) {
        case 0:
            if (*(void **)(p2 + 0x2d0) == NULL) {
                *(u8 *)(sub + 0x34) = 1;
            } else if (*(int *)(sub + 0x30) != 0) {
                if (ObjGroup_ContainsObject(*(int *)(p2 + 0x2d0), *(int *)(sub + 0x30)) == 0) {
                    *(int *)(p2 + 0x2d0) = ObjGroup_FindNearestObjectForObject(*(int *)(sub + 0x30), obj, 0);
                    if (*(void **)(p2 + 0x2d0) == NULL) {
                        *(u8 *)(sub + 0x34) = 1;
                    }
                    *(f32 *)(p2 + 0x280) = lbl_803E62A8;
                }
            }
            break;
        case 1:
            if (*(void **)(p2 + 0x2d0) == NULL) {
                *(u8 *)(sub + 0x34) = 1;
            }
            break;
        }
        if (*(s16 *)(sub + 0x1c) == -1 && (ptr = *(char **)(sub + 0x3c)) != NULL) {
            if ((**(int (**)(char *))(*(int *)(*(int *)(ptr + 0x68))  + 0x20))(ptr) == 0) {
                *(int *)(sub + 0x3c) = 0;
                *(u8 *)(sub + 0x34) = 1;
            }
        }
        return 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80201358(int obj, int p2)
{
    extern int Stack_IsFull(int sp);
    extern void Stack_Push(int sp, int *args);
    extern void ObjMsg_SendToObject(int, int, int, int);
    extern int Obj_GetYawDeltaToObject(int, int, f32 *);
    extern void ObjAnim_SetCurrentMove(int obj, int n, f32 v, int m);
    extern f32 sqrtf(f32 x);
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E6310;
    extern f32 lbl_803E6314;
    extern f32 lbl_803E6318;
    extern f32 lbl_803E631C;
    extern f32 lbl_803E6320;
    int sub = *(int *)(*(int *)(obj + 0xb8) + 0x40c);
    int c30 = *(int *)(sub + 0x30);
    int c2c = *(int *)(sub + 0x2c);
    int tmpB;
    int tmpA;
    int t;
    int q;
    f32 z;
    f32 dist;
    struct {
        f32 v[3];
        f32 out[3];
    } stk;
    int msgA[3];
    int msgB[3];
    int msgC[3];

    z = lbl_803E62A8;
    *(f32 *)(p2 + 0x280) = lbl_803E62A8;
    *(f32 *)(p2 + 0x284) = z;
    *(u8 *)(sub + 0x14) |= 2;
    if (*(void **)(sub + 0x18) == NULL && *(s16 *)(sub + 0x1c) != -1) {
        tmpA = *(int *)(sub + 0x30);
        tmpB = *(int *)(sub + 0x2c);
        q = *(int *)(sub + 0x24);
        msgA[0] = *(int *)(sub + 0x28);
        msgA[1] = tmpB;
        msgA[2] = tmpA;
        if (Stack_IsFull(q) == 0) {
            Stack_Push(q, msgA);
        }
        q = *(int *)(sub + 0x24);
        msgB[0] = 8;
        msgB[1] = c2c;
        msgB[2] = c30;
        if (Stack_IsFull(q) == 0) {
            Stack_Push(q, msgB);
        }
        *(u8 *)(sub + 0x34) = 1;
        tmpA = *(s16 *)(sub + 0x1c);
        q = *(int *)(sub + 0x24);
        msgC[0] = 9;
        msgC[1] = 0;
        msgC[2] = tmpA;
        if (Stack_IsFull(q) == 0) {
            Stack_Push(q, msgC);
        }
        *(u8 *)(sub + 0x34) = 1;
        return 0;
    } else {
        *(u8 *)(sub + 0x15) |= 4;
        if (*(int *)(sub + 0x18) != 0 && (*(u32 *)(p2 + 0x314) & 0x200) != 0) {
            t = *(int *)(p2 + 0x2d0);
            stk.v[0] = *(f32 *)(t + 0xc) - *(f32 *)(obj + 0xc);
            stk.v[1] = *(f32 *)(t + 0x10) - *(f32 *)(obj + 0x10);
            stk.v[2] = *(f32 *)(t + 0x14) - *(f32 *)(obj + 0x14);
            dist = sqrtf(stk.v[0] * stk.v[0] + stk.v[2] * stk.v[2]);
            stk.v[1] = stk.v[1] * lbl_803E6310;
            dist = dist / lbl_803E6314;
            stk.out[1] = -(dist * (lbl_803E6318 * dist) - stk.v[1]) / dist;
            stk.out[1] = stk.out[1] * lbl_803E631C;
            stk.out[0] = lbl_803E62A8;
            stk.out[2] = lbl_803E6320;
            ObjMsg_SendToObject(*(int *)(sub + 0x18), 0x11, obj, 0x11);
            (**(void (**)(int, f32 *))(*(int *)(*(int *)(*(int *)(sub + 0x18) + 0x68)) + 0x24))(*(int *)(sub + 0x18), stk.out);
            *(int *)(sub + 0x18) = 0;
            *(s16 *)(sub + 0x1c) = -1;
        }
        *(s16 *)(obj + 0) += Obj_GetYawDeltaToObject(obj, *(int *)(p2 + 0x2d0), 0);
        *(u8 *)(p2 + 0x34d) = 0x11;
        if (*(s8 *)(p2 + 0x27a) != 0) {
            ObjAnim_SetCurrentMove(obj, 0x12, lbl_803E62A8, 0);
            *(u8 *)(p2 + 0x346) = 0;
        }
        if (*(s8 *)(p2 + 0x346) != 0) {
            *(u8 *)(sub + 0x34) = 1;
        }
        return 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80200E44(int obj, int p2, f32 t)
{
    extern int Stack_IsFull(int sp);
    extern void Stack_Push(int sp, int *args);
    extern int ObjGroup_ContainsObject(int, int);
    extern int *ObjGroup_GetObjects(int, int *);
    extern int ObjGroup_FindNearestObject(int, int, f32 *);
    extern int Obj_GetPlayerObject(void);
    extern int Obj_GetYawDeltaToObject(int, int, f32 *);
    extern void ObjAnim_SetCurrentMove(int obj, int n, f32 v, int m);
    extern int *seqFn_800394a0(void);
    extern s16 *objModelGetVecFn_800395d8(int, int);
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E62B4;
    extern f32 lbl_803E62C4;
    extern f32 lbl_803E62CC;
    extern f32 lbl_803E62D0;
    extern int lbl_8032971C[];
    extern f32 lbl_8032972C[];
    int blob = *(int *)(obj + 0xb8);
    int sub = *(int *)(blob + 0x40c);
    int c30 = *(int *)(sub + 0x30);
    int tmpA;
    int tmpB;
    int i;
    int found;
    int q;
    int *objs;
    int player;
    int d;
    int flag;
    int zero;
    int *ptr;
    s16 *vec;
    f32 frac;
    int msg0[3];
    int msgA[3];
    int msgB[3];
    int msgC[3];
    int msgD[3];
    int msgE[3];
    int msgF[3];
    int msgG[3];
    int msgH[3];
    int msgI[3];
    int cnt1;
    int cnt2;
    f32 yawf;

    *(u8 *)(sub + 0x14) |= 2;
    *(u8 *)(sub + 0x15) &= ~4;
    if (ObjGroup_ContainsObject(*(int *)(p2 + 0x2d0), c30) == 0) {
        ObjGroup_GetObjects(c30, &cnt1);
        if (cnt1 == 0) {
            player = Obj_GetPlayerObject();
            q = *(int *)(sub + 0x24);
            msg0[0] = 0xf;
            msg0[1] = 1;
            msg0[2] = player;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msg0);
            }
            *(u8 *)(sub + 0x34) = 1;
            return 0;
        }
    }
    q = *(int *)(p2 + 0x2d0);
    found = 0;
    objs = ObjGroup_GetObjects(3, &cnt2);
    for (i = 0; i < cnt2; i++) {
        if (*(s16 *)(*objs + 0x46) == 0x539) {
            if ((u32)(**(int (**)(int, int, int))(*(int *)(*(int *)(*objs + 0x68)) + 0x24))(*objs, 0x83, 0) == (u32)q) {
                found = 1;
            }
        }
        objs++;
    }
    if (found == 0) {
        if ((u32)obj == (u32)ObjGroup_FindNearestObject(3, *(int *)(p2 + 0x2d0), 0)) {
            *(int *)(sub + 0x3c) = *(int *)(p2 + 0x2d0);
            tmpA = *(int *)(sub + 0x30);
            tmpB = *(int *)(sub + 0x2c);
            q = *(int *)(sub + 0x24);
            msgA[0] = *(int *)(sub + 0x28);
            msgA[1] = tmpB;
            msgA[2] = tmpA;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgA);
            }
            q = *(int *)(sub + 0x24);
            msgB[0] = 0xc;
            msgB[1] = 0;
            msgB[2] = 3;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgB);
            }
            *(u8 *)(sub + 0x34) = 1;
            q = *(int *)(sub + 0x24);
            msgC[0] = 9;
            msgC[1] = 0;
            msgC[2] = c30;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgC);
            }
            *(u8 *)(sub + 0x34) = 1;
            tmpA = *(int *)(sub + 0x3c);
            q = *(int *)(sub + 0x24);
            msgD[0] = 7;
            msgD[1] = 1;
            msgD[2] = tmpA;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgD);
            }
            *(u8 *)(sub + 0x34) = 1;
            return 0;
        }
    }
    sub = *(int *)(blob + 0x40c);
    *(u8 *)(p2 + 0x34d) = 0x1f;
    if (*(s8 *)(p2 + 0x27a) != 0) {
        ObjAnim_SetCurrentMove(obj, 0xf, lbl_803E62A8, 0);
        *(u8 *)(p2 + 0x346) = 0;
    }
    if (*(void **)(sub + 0x3c) != NULL) {
        if (ObjGroup_ContainsObject(*(int *)(p2 + 0x2d0), c30) != 0) {
            tmpA = *(int *)(sub + 0x30);
            tmpB = *(int *)(sub + 0x2c);
            q = *(int *)(sub + 0x24);
            msgE[0] = *(int *)(sub + 0x28);
            msgE[1] = tmpB;
            msgE[2] = tmpA;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgE);
            }
            q = *(int *)(sub + 0x24);
            msgF[0] = 0xc;
            msgF[1] = 0;
            msgF[2] = 3;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgF);
            }
            *(u8 *)(sub + 0x34) = 1;
            tmpA = *(int *)(sub + 0x3c);
            q = *(int *)(sub + 0x24);
            msgG[0] = 0xd;
            msgG[1] = 1;
            msgG[2] = tmpA;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgG);
            }
            *(u8 *)(sub + 0x34) = 1;
            return 0;
        }
    }
    frac = (f32)*(u8 *)(blob + 0x406) / lbl_803E62C4;
    fn_80202C78(obj, *(int *)(p2 + 0x2d0), lbl_803E62B4, frac, lbl_803E62CC, t);
    if (((u32)*(u8 *)(sub + 0x44) >> 5 & 1) != 0) {
        fn_80202A2C(obj, lbl_8032971C, lbl_8032972C, 4, frac);
    }
    player = Obj_GetPlayerObject();
    d = (s16)Obj_GetYawDeltaToObject(obj, player, &yawf);
    flag = 0;
    if (d >= 0) {
    } else {
        d = -d;
    }
    if (d < 0x1c71 && yawf < lbl_803E62D0) {
        flag = 1;
    }
    if (flag != 0) {
        ptr = seqFn_800394a0();
        q = 1;
        ptr = ptr + 1;
        zero = 0;
        for (; q < 9; q++) {
            vec = objModelGetVecFn_800395d8(obj, *ptr);
            if (vec != 0) {
                vec[2] = zero;
                vec[0] = zero;
            }
            ptr++;
        }
        player = Obj_GetPlayerObject();
        *(int *)(p2 + 0x2d0) = player;
        tmpA = *(int *)(sub + 0x30);
        tmpB = *(int *)(sub + 0x2c);
        q = *(int *)(sub + 0x24);
        msgH[0] = *(int *)(sub + 0x28);
        msgH[1] = tmpB;
        msgH[2] = tmpA;
        if (Stack_IsFull(q) == 0) {
            Stack_Push(q, msgH);
        }
        q = *(int *)(sub + 0x24);
        msgI[0] = 2;
        msgI[1] = 0;
        msgI[2] = 0;
        if (Stack_IsFull(q) == 0) {
            Stack_Push(q, msgI);
        }
        *(u8 *)(sub + 0x34) = 1;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80201BD8(int obj, int p2, f32 t)
{
    extern int Stack_IsFull(int sp);
    extern void Stack_Push(int sp, int *args);
    extern void Sfx_KeepAliveLoopedObjectSound(int, int);
    extern void ObjHits_EnableObject(int);
    extern void ObjHits_ClearHitVolumes(int);
    extern int RandomTimer_UpdateRangeTrigger(int, f32, f32);
    extern void Sfx_PlayFromObject(int, int);
    extern void ObjAnim_SetCurrentMove(int obj, int n, f32 v, int m);
    extern void ObjAnim_SampleRootCurvePhase(int, f32, int);
    extern int Obj_GetPlayerObject(void);
    extern int Obj_GetYawDeltaToObject(int, int, f32 *);
    extern int *seqFn_800394a0(void);
    extern s16 *objModelGetVecFn_800395d8(int, int);
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E62C4;
    extern f32 lbl_803E62C8;
    extern f32 lbl_803E62CC;
    extern f32 lbl_803E62D0;
    extern f32 lbl_803E62F4;
    extern f32 lbl_803E6300;
    extern f32 lbl_803E6324;
    extern f32 lbl_803E6328;
    extern f32 lbl_803E632C;
    extern f32 lbl_803E6330;
    extern int lbl_803296FC[];
    extern f32 lbl_8032970C[];
    int blob = *(int *)(obj + 0xb8);
    int sub = *(int *)(blob + 0x40c);
    s16 h;
    register int q;
    register int *ptr;
    int tmpB;
    int tmpA;
    int tmp2B;
    int tmp2A;
    int player;
    int flag;
    int d;
    int zero;
    s16 *vec;
    s16 sa;
    s16 sb;
    f32 frac;
    int msgA[3];
    int msgB[3];
    int msgC[3];
    int msgD[3];
    f32 yawf;

    *(u8 *)(sub + 0x14) |= 2;
    *(u8 *)(sub + 0x15) &= ~4;
    Sfx_KeepAliveLoopedObjectSound(obj, 0x441);
    if (*(s8 *)(p2 + 0x27a) != 0) {
        ObjHits_EnableObject(obj);
    }
    ObjHits_ClearHitVolumes(obj);
    *(f32 *)(p2 + 0x2a0) = lbl_803E62F4;
    if (*(void **)(sub + 0x18) == NULL) {
        h = *(s16 *)(sub + 0x1c);
        if (h != -1) {
            tmpA = *(int *)(sub + 0x30);
            tmpB = *(int *)(sub + 0x2c);
            q = *(int *)(sub + 0x24);
            msgA[0] = *(int *)(sub + 0x28);
            msgA[1] = tmpB;
            msgA[2] = tmpA;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgA);
            }
            q = *(int *)(sub + 0x24);
            msgB[0] = 9;
            msgB[1] = 0;
            msgB[2] = h;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgB);
            }
            *(u8 *)(sub + 0x34) = 1;
            *(s16 *)(sub + 0x1c) = -1;
        }
        if (*(s8 *)(p2 + 0x27a) != 0) {
            ObjAnim_SetCurrentMove(obj, 0xf, lbl_803E62A8, 0);
            *(u8 *)(p2 + 0x346) = 0;
        }
        frac = (f32)*(u8 *)(blob + 0x406) / lbl_803E62C4;
        if (RandomTimer_UpdateRangeTrigger(sub + 0x4c, lbl_803E62C8, lbl_803E632C) != 0) {
            Sfx_PlayFromObject(obj, 0x43f);
        }
    } else {
        if (RandomTimer_UpdateRangeTrigger(sub + 0x48, lbl_803E62C8, lbl_803E632C) != 0) {
            Sfx_PlayFromObject(obj, 0x440);
        }
        if (*(s8 *)(p2 + 0x27a) != 0) {
            ObjAnim_SetCurrentMove(obj, 0x11, lbl_803E62A8, 0);
            *(u8 *)(p2 + 0x346) = 0;
        }
        *(f32 *)(p2 + 0x2a0) = lbl_803E6300;
        frac = (f32)*(u8 *)(blob + 0x406) / lbl_803E6324;
    }
    *(u8 *)(p2 + 0x34d) = 0x1f;
    if (fn_80202DA4((u8 *)obj, *(u8 **)(p2 + 0x2d0), lbl_803E6330, frac, lbl_803E62CC, t) != 0) {
        *(u8 *)(sub + 0x34) = 1;
    }
    if (((u32)*(u8 *)(sub + 0x44) >> 5 & 1) != 0) {
        fn_80202A2C(obj, lbl_803296FC, lbl_8032970C, 4, frac);
    } else if (*(void **)(sub + 0x18) == NULL) {
        player = Obj_GetPlayerObject();
        d = (s16)Obj_GetYawDeltaToObject(obj, player, &yawf);
        flag = 0;
        if (d >= 0) {
        } else {
            d = -d;
        }
        if (d < 0x1c71 && yawf < lbl_803E62D0) {
            flag = 1;
        }
        if (flag != 0) {
            ptr = seqFn_800394a0();
            q = 1;
            ptr = ptr + 1;
            zero = 0;
            for (; q < 9; q++) {
                vec = objModelGetVecFn_800395d8(obj, *ptr);
                if (vec != 0) {
                    vec[2] = zero;
                    vec[0] = zero;
                }
                ptr++;
            }
            player = Obj_GetPlayerObject();
            *(int *)(p2 + 0x2d0) = player;
            tmp2A = *(int *)(sub + 0x30);
            tmp2B = *(int *)(sub + 0x2c);
            q = *(int *)(sub + 0x24);
            msgC[0] = *(int *)(sub + 0x28);
            msgC[1] = tmp2B;
            msgC[2] = tmp2A;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgC);
            }
            q = *(int *)(sub + 0x24);
            msgD[0] = 2;
            msgD[1] = 0;
            msgD[2] = 0;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgD);
            }
            *(u8 *)(sub + 0x34) = 1;
        }
    }
    if (((u32)*(u8 *)(sub + 0x44) >> 6 & 1) != 0) {
        ptr = seqFn_800394a0();
        q = 1;
        ptr = ptr + 1;
        zero = 0;
        for (; q < 9; q++) {
            vec = objModelGetVecFn_800395d8(obj, *ptr);
            if (vec != 0) {
                vec[2] = zero;
                vec[0] = zero;
            }
            ptr++;
        }
    } else if (*(void **)(sub + 0x18) == NULL) {
        d = -(lbl_803E6328 * *(f32 *)(p2 + 0x280));
        flag = -(lbl_803E6328 * *(f32 *)(p2 + 0x284));
        d = (s16)d;
        if (d < -0x500) {
            d = -0x500;
        } else if (d > 0x500) {
            d = 0x500;
        }
        sa = d;
        flag = (s16)flag;
        if (flag < -0x500) {
            flag = -0x500;
        } else if (flag > 0x500) {
            flag = 0x500;
        }
        sb = flag;
        ptr = seqFn_800394a0();
        q = 1;
        ptr = ptr + 1;
        for (; q < 9; q++) {
            vec = objModelGetVecFn_800395d8(obj, *ptr);
            if (vec != 0) {
                vec[2] = sb;
                vec[0] = sa;
            }
            ptr++;
        }
    }
    ObjAnim_SampleRootCurvePhase(obj, *(f32 *)(p2 + 0x280), p2 + 0x2a0);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma opt_loop_invariants off
void dbstealerworm_update(u8 *objp)
{
    extern void Stack_Push(int sp, int *args);
    extern int allocModelStruct_800139e8(int, int);
    extern uint GameBit_Get(int);
    extern void ObjGroup_AddObject(int, int);
    extern void ObjAnim_SetCurrentMove(int obj, int n, f32 v, int m);
    extern int ObjMsg_Pop(int, u32 *, int *, int *);
    extern void ObjMsg_SendToObject(int, int, int, int);
    extern void objLightFn_8009a1dc(int, f32, int, int, int);
    extern f32 sqrtf(f32);
    extern int *gMapEventInterface;
    extern void **gBaddieControlInterface;
    extern int *gObjectTriggerInterface;
    extern int *gPlayerInterface;
    extern f32 timeDelta;
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E62FC;
    extern f32 lbl_803E6388;
    extern f32 lbl_803E638C;
    extern u8 lbl_803AD0C0[];
    extern u8 lbl_803293B8[];
    char *st = (char *)lbl_803AD0C0;
    char *tbl = (char *)lbl_803293B8;
    int blob = *(int *)(objp + 0xb8);
    int data = *(int *)(objp + 0x4c);
    int sub = *(int *)(blob + 0x40c);
    int obj = (int)objp;
    int off;
    char *entry;
    int n;
    int sub2;
    int sub3;
    int t;
    struct {
        u32 msg;
        int argA;
        int argB;
        f32 v[3];
    } stk;

    *(u8 *)(obj + 0xaf) |= 8;
    if ((u32)*(u8 *)(sub + 0x44) >> 4 & 1) {
        entry = (char *)((int)(tbl + *(s16 *)(data + 0x24) * 8) + 0x15c);
        *(int *)(sub + 0x24) = allocModelStruct_800139e8(0x14, 0xc);
        n = *(s16 *)(entry + 4);
        off = n * 0xc;
        for (; n != 0; n--) {
            Stack_Push(*(int *)(sub + 0x24), (int *)(*(int *)entry + (off -= 12)));
        }
        *(u8 *)(sub + 0x34) = 1;
        ((AnimFlags44 *)(sub + 0x44))->flag10 = 0;
    }
    if (GameBit_Get(*(s16 *)(blob + 0x3f6)) != 0) {
        if (*(int *)(obj + 0xf4) != 0) {
            if ((*(u8 *)(blob + 0x404) & 4) == 0 &&
                ((int (*)(int))((void **)*(int *)gMapEventInterface)[26])(*(int *)(data + 0x14)) != 0) {
                ((void (*)(int, int, int, int, int, int, int, f32))((void **)*gBaddieControlInterface)[22])(obj, data, blob, 0x10, 7, 0x10a, 0x26, lbl_803E62FC);
                ObjGroup_AddObject(obj, 3);
                *(s16 *)(blob + 0x402) = 0;
                ObjAnim_SetCurrentMove(obj, 8, lbl_803E62A8, 0x10);
                *(u8 *)(blob + 0x346) = 0;
                *(u8 *)(obj + 0x36) = 0xff;
                *(u8 *)(obj + 0xaf) |= 8;
            }
        } else if (*(int *)(obj + 0xf8) == 0) {
            *(f32 *)(obj + 0xc) = *(f32 *)(data + 8);
            *(f32 *)(obj + 0x10) = *(f32 *)(data + 0xc);
            *(f32 *)(obj + 0x14) = *(f32 *)(data + 0x10);
            ((void (*)(int, int, int))((void **)*(int *)gObjectTriggerInterface)[18])(*(s8 *)(data + 0x2e), obj, -1);
            *(int *)(obj + 0xf8) = 1;
        } else {
            if (((int (*)(int, int, int))((void **)*gBaddieControlInterface)[12])(obj, blob, 0) == 0) {
                *(s16 *)(blob + 0x402) = 0;
            } else {
                t = *(int *)(blob + 0x2d0);
                if (*(void **)(blob + 0x2d0) != NULL) {
                    stk.v[0] = *(f32 *)(t + 0x18) - *(f32 *)(obj + 0x18);
                    stk.v[1] = *(f32 *)(t + 0x1c) - *(f32 *)(obj + 0x1c);
                    stk.v[2] = *(f32 *)(t + 0x20) - *(f32 *)(obj + 0x20);
                    *(f32 *)(blob + 0x2c0) = sqrtf(stk.v[2] * stk.v[2] + (stk.v[0] * stk.v[0] + stk.v[1] * stk.v[1]));
                }
                stk.msg = 0;
                stk.argA = 0;
                sub2 = *(int *)(*(int *)(obj + 0xb8) + 0x40c);
                while (ObjMsg_Pop(obj, &stk.msg, &stk.argB, &stk.argA) != 0) {
                    if (stk.msg == 0x11 && *(s16 *)(sub2 + 0x1c) != -1) {
                        ObjMsg_SendToObject(*(int *)(sub2 + 0x18), 0x11, obj, 0x14);
                        *(int *)(sub2 + 0x18) = 0;
                        *(s16 *)(sub2 + 0x1c) = -1;
                        ObjAnim_SetCurrentMove(obj, 0xf, lbl_803E62A8, 0);
                    }
                }
                if (((int (*)(int, int, int, int, char *, char *, int, char *))((void **)*gBaddieControlInterface)[20])(obj, blob, blob + 0x35c, *(s16 *)(blob + 0x3f4), tbl + 0x2ac, tbl + 0x324, 1, st) != 0) {
                    *(f32 *)(st + 0xc) = *(f32 *)(obj + 0xc);
                    *(f32 *)(st + 0x10) = *(f32 *)(obj + 0x10);
                    *(f32 *)(st + 0x14) = *(f32 *)(obj + 0x14);
                    objLightFn_8009a1dc(obj, lbl_803E638C, (int)st, 1, 0);
                }
                if (*(s16 *)(blob + 0x402) == 0) {
                    fn_80203144(obj, blob, blob);
                } else {
                    sub3 = *(int *)(blob + 0x40c);
                    fn_80203000(obj, blob);
                    ((void (*)(int, int, f32, int))((void **)*gBaddieControlInterface)[11])(obj, blob, lbl_803E6388, -1);
                    if ((*(u8 *)(sub3 + 0x15) & 4) == 0) {
                        ((void (*)(int, int, f32, int))((void **)*(int *)gPlayerInterface)[12])(obj, blob, timeDelta, 4);
                    }
                    *(int *)(blob + 0x3e0) = *(int *)(obj + 0xc0);
                    *(int *)(obj + 0xc0) = 0;
                    ((void (*)(int, int, f32, f32, int, int))((void **)*(int *)gPlayerInterface)[2])(obj, blob, timeDelta, timeDelta, (int)(st + 0x34), (int)(st + 0x18));
                    *(int *)(obj + 0xc0) = *(int *)(blob + 0x3e0);
                }
            }
        }
    }
}
#pragma opt_loop_invariants reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802017A4(int obj, int p2, f32 t)
{
    extern int Stack_IsFull(int sp);
    extern void Stack_Push(int sp, int *args);
    extern void ObjHits_EnableObject(int);
    extern void ObjHits_ClearHitVolumes(int);
    extern void ObjAnim_SetCurrentMove(int obj, int n, f32 v, int m);
    extern void ObjAnim_SampleRootCurvePhase(int, f32, int);
    extern int Obj_GetPlayerObject(void);
    extern int Obj_GetYawDeltaToObject(int, int, f32 *);
    extern int *seqFn_800394a0(void);
    extern s16 *objModelGetVecFn_800395d8(int, int);
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E62CC;
    extern f32 lbl_803E62D0;
    extern f32 lbl_803E62B4;
    extern f32 lbl_803E62F4;
    extern f32 lbl_803E6300;
    extern f32 lbl_803E6324;
    extern f32 lbl_803E6328;
    extern int lbl_803296FC[];
    extern f32 lbl_8032970C[];
    int blob = *(int *)(obj + 0xb8);
    int sub = *(int *)(blob + 0x40c);
    s16 h;
    int q;
    int *ptr;
    int tmpB;
    int tmpA;
    int tmp2B;
    int tmp2A;
    int player;
    int flag;
    int d;
    int zero;
    s16 *vec;
    s16 sa;
    s16 sb;
    f32 frac;
    int msgA[3];
    int msgB[3];
    int msgC[3];
    int msgD[3];
    f32 yawf;

    *(u8 *)(sub + 0x14) |= 2;
    *(u8 *)(sub + 0x15) &= ~4;
    if (*(s8 *)(p2 + 0x27a) != 0) {
        ObjHits_EnableObject(obj);
        ObjHits_ClearHitVolumes(obj);
    }
    *(f32 *)(p2 + 0x2a0) = lbl_803E62F4;
    if (*(void **)(sub + 0x18) == NULL) {
        h = *(s16 *)(sub + 0x1c);
        if (h != -1) {
            tmpA = *(int *)(sub + 0x30);
            tmpB = *(int *)(sub + 0x2c);
            q = *(int *)(sub + 0x24);
            msgA[0] = *(int *)(sub + 0x28);
            msgA[1] = tmpB;
            msgA[2] = tmpA;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgA);
            }
            q = *(int *)(sub + 0x24);
            msgB[0] = 9;
            msgB[1] = 0;
            msgB[2] = h;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgB);
            }
            *(u8 *)(sub + 0x34) = 1;
            *(s16 *)(sub + 0x1c) = -1;
        }
    } else {
        if (*(s8 *)(p2 + 0x27a) != 0) {
            ObjAnim_SetCurrentMove(obj, 0x11, lbl_803E62A8, 0);
            *(u8 *)(p2 + 0x346) = 0;
        }
        *(f32 *)(p2 + 0x2a0) = lbl_803E6300;
        frac = (f32)*(u8 *)(blob + 0x406) / lbl_803E6324;
    }
    *(u8 *)(p2 + 0x34d) = 0x1f;
    if (fn_80202C78(obj, *(int *)(p2 + 0x2d0), lbl_803E62B4, frac, lbl_803E62CC, t) != 0) {
        *(u8 *)(sub + 0x34) = 1;
    }
    if (((u32)*(u8 *)(sub + 0x44) >> 5 & 1) != 0) {
        fn_80202A2C(obj, lbl_803296FC, lbl_8032970C, 4, frac);
    } else if (*(void **)(sub + 0x18) == NULL) {
        player = Obj_GetPlayerObject();
        d = (s16)Obj_GetYawDeltaToObject(obj, player, &yawf);
        flag = 0;
        if (d >= 0) {
        } else {
            d = -d;
        }
        if (d < 0x1c71 && yawf < lbl_803E62D0) {
            flag = 1;
        }
        if (flag != 0) {
            ptr = seqFn_800394a0();
            q = 1;
            ptr = ptr + 1;
            zero = 0;
            for (; q < 9; q++) {
                vec = objModelGetVecFn_800395d8(obj, *ptr);
                if (vec != 0) {
                    vec[2] = zero;
                    vec[0] = zero;
                }
                ptr++;
            }
            player = Obj_GetPlayerObject();
            *(int *)(p2 + 0x2d0) = player;
            tmp2A = *(int *)(sub + 0x30);
            tmp2B = *(int *)(sub + 0x2c);
            q = *(int *)(sub + 0x24);
            msgC[0] = *(int *)(sub + 0x28);
            msgC[1] = tmp2B;
            msgC[2] = tmp2A;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgC);
            }
            q = *(int *)(sub + 0x24);
            msgD[0] = 2;
            msgD[1] = 0;
            msgD[2] = 0;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgD);
            }
            *(u8 *)(sub + 0x34) = 1;
        }
    }
    if (((u32)*(u8 *)(sub + 0x44) >> 6 & 1) != 0) {
        ptr = seqFn_800394a0();
        q = 1;
        ptr = ptr + 1;
        zero = 0;
        for (; q < 9; q++) {
            vec = objModelGetVecFn_800395d8(obj, *ptr);
            if (vec != 0) {
                vec[2] = zero;
                vec[0] = zero;
            }
            ptr++;
        }
    } else if (*(void **)(sub + 0x18) == NULL) {
        d = -(lbl_803E6328 * *(f32 *)(p2 + 0x280));
        flag = -(lbl_803E6328 * *(f32 *)(p2 + 0x284));
        d = (s16)d;
        if (d < -0x500) {
            d = -0x500;
        } else if (d > 0x500) {
            d = 0x500;
        }
        sa = d;
        flag = (s16)flag;
        if (flag < -0x500) {
            flag = -0x500;
        } else if (flag > 0x500) {
            flag = 0x500;
        }
        sb = flag;
        ptr = seqFn_800394a0();
        q = 1;
        ptr = ptr + 1;
        for (; q < 9; q++) {
            vec = objModelGetVecFn_800395d8(obj, *ptr);
            if (vec != 0) {
                vec[2] = sb;
                vec[0] = sa;
            }
            ptr++;
        }
    }
    ObjAnim_SampleRootCurvePhase(obj, *(f32 *)(p2 + 0x280), p2 + 0x2a0);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80204BF8(int obj)
{
    extern int Obj_GetPlayerObject(void);
    extern uint GameBit_Get(int);
    extern f32 Vec_xzDistance(int, int);
    extern int Sfx_IsPlayingFromObjectChannel(int, int);
    extern void Sfx_PlayFromObject(int, int);
    extern void Sfx_StopObjectChannel(int, int);
    extern f32 timeDelta;
    extern f32 lbl_803E639C;
    extern f32 lbl_803E63A0;
    extern f32 lbl_803E63A4;
    extern f32 lbl_803E63A8;
    int data = *(int *)(obj + 0x4c);
    int blob = *(int *)(obj + 0xb8);
    int player;
    int h;
    f32 d;
    f32 k;

    player = Obj_GetPlayerObject();
    if ((u32)player == 0) {
        return;
    }
    switch (*(s16 *)(blob + 4)) {
    case 0:
        if (GameBit_Get(*(s16 *)(blob + 6)) != 0 && *(u8 *)(blob + 0xc) != 1) {
            if (Vec_xzDistance(obj + 0x18, player + 0x18) < lbl_803E639C) {
                if (*(f32 *)(obj + 0x10) < lbl_803E63A0 + *(f32 *)(data + 0xc)) {
                    if (Sfx_IsPlayingFromObjectChannel(obj, 8) == 0) {
                        Sfx_PlayFromObject(obj, 0x116);
                        *(u8 *)(blob + 0xd) = 1;
                    }
                    *(f32 *)(obj + 0x10) += timeDelta;
                    if (*(f32 *)(obj + 0x10) >= lbl_803E63A0 + *(f32 *)(data + 0xc)) {
                        *(f32 *)(obj + 0x10) = lbl_803E63A0 + *(f32 *)(data + 0xc);
                        *(s16 *)(blob + 4) = 1;
                        Sfx_StopObjectChannel(obj, 8);
                    }
                }
            }
        } else {
            if (*(u8 *)(blob + 0xc) == 1) {
                if (Vec_xzDistance(obj + 0x18, player + 0x18) < lbl_803E639C) {
                    if (*(f32 *)(obj + 0x10) < (k = lbl_803E63A0) + *(f32 *)(data + 0xc)) {
                        *(f32 *)(obj + 0x10) += timeDelta;
                        if (*(f32 *)(obj + 0x10) >= k + *(f32 *)(data + 0xc)) {
                            *(f32 *)(obj + 0x10) = k + *(f32 *)(data + 0xc);
                            *(s16 *)(blob + 4) = 1;
                        }
                    }
                }
            }
        }
        break;
    case 1:
        *(s16 *)(blob + 4) = 2;
        *(s16 *)(blob + 0xa) = 0x64;
        break;
    case 2:
        h = *(s16 *)(blob + 0xa);
        if (h != 0) {
            *(s16 *)(blob + 0xa) = h - (int)timeDelta;
            if (*(s16 *)(blob + 0xa) <= 0) {
                *(s16 *)(blob + 0xa) = 0;
            }
        } else {
            d = Vec_xzDistance(obj + 0x18, player + 0x18);
            if (d < lbl_803E63A4) {
                if (*(f32 *)(obj + 0x10) == lbl_803E63A0 + *(f32 *)(data + 0xc)) {
                    *(s16 *)(blob + 4) = 3;
                    if (Sfx_IsPlayingFromObjectChannel(obj, 8) == 0) {
                        Sfx_PlayFromObject(obj, 0x1cb);
                        *(u8 *)(blob + 0xd) = 1;
                    }
                } else if (*(f32 *)(obj + 0x10) == d - lbl_803E63A8) {
                    *(s16 *)(blob + 4) = 4;
                    if (Sfx_IsPlayingFromObjectChannel(obj, 8) == 0) {
                        Sfx_PlayFromObject(obj, 0x1cb);
                        *(u8 *)(blob + 0xd) = 1;
                    }
                }
            } else {
                if (*(f32 *)(player + 0x10) < *(f32 *)(data + 0xc)) {
                    *(s16 *)(blob + 4) = 3;
                    if (*(u8 *)(blob + 0xd) == 1) {
                        *(u8 *)(blob + 0xd) = 0;
                    }
                } else if (*(f32 *)(player + 0x10) > *(f32 *)(data + 0xc)) {
                    *(s16 *)(blob + 4) = 4;
                    if (*(u8 *)(blob + 0xd) == 1) {
                        *(u8 *)(blob + 0xd) = 0;
                    }
                }
            }
        }
        break;
    case 3:
        if (*(f32 *)(obj + 0x10) > *(f32 *)(data + 0xc) - (k = lbl_803E63A8)) {
            *(f32 *)(obj + 0x10) -= timeDelta;
            if (*(f32 *)(obj + 0x10) <= *(f32 *)(data + 0xc) - k) {
                *(f32 *)(obj + 0x10) = *(f32 *)(data + 0xc) - k;
                *(s16 *)(blob + 4) = 2;
                Sfx_StopObjectChannel(obj, 8);
                *(s16 *)(blob + 0xa) = 0x64;
            }
            Vec_xzDistance(obj + 0x18, player + 0x18);
        } else {
            Sfx_StopObjectChannel(obj, 8);
            Vec_xzDistance(obj + 0x18, player + 0x18);
            *(s16 *)(blob + 4) = 2;
            *(s16 *)(blob + 0xa) = 0x64;
        }
        break;
    case 4:
        if (*(f32 *)(obj + 0x10) < (k = lbl_803E63A0) + *(f32 *)(data + 0xc)) {
            *(f32 *)(obj + 0x10) += timeDelta;
            if (*(f32 *)(obj + 0x10) >= k + *(f32 *)(data + 0xc)) {
                *(f32 *)(obj + 0x10) = k + *(f32 *)(data + 0xc);
                *(s16 *)(blob + 4) = 2;
                *(s16 *)(blob + 0xa) = 0x64;
                Sfx_StopObjectChannel(obj, 8);
            }
            Vec_xzDistance(obj + 0x18, player + 0x18);
        } else {
            *(s16 *)(blob + 4) = 2;
            *(s16 *)(blob + 0xa) = 0x64;
            Sfx_StopObjectChannel(obj, 8);
            Vec_xzDistance(obj + 0x18, player + 0x18);
        }
        break;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80200A70(int obj, int p2, f32 t)
{
    extern int Stack_IsFull(int sp);
    extern void Stack_Push(int sp, int *args);
    extern void fn_80137948(char *, ...);
    extern void ObjAnim_SetCurrentMove(int obj, int n, f32 v, int m);
    extern int Obj_GetPlayerObject(void);
    extern int *ObjGroup_GetObjects(int, int *);
    extern f32 Vec_xzDistance(int, int);
    extern f32 vec3f_distanceSquared(int, int);
    extern f32 sqrtf(f32);
    extern int randomGetRange(int, int);
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E62B0;
    extern f32 lbl_803E62B8;
    extern f32 lbl_803E6300;
    extern f32 lbl_803E6304;
    extern f32 lbl_803E6308;
    extern f32 lbl_803E630C;
    extern f32 lbl_803E62CC;
    extern u8 lbl_803293B8[];
    char *tbl = (char *)lbl_803293B8;
    int blob = *(int *)(obj + 0xb8);
    int sub = *(int *)(blob + 0x40c);
    int c30 = *(int *)(sub + 0x30);
    s16 h;
    int n;
    int q;
    int *objs;
    int player;
    int o;
    int best;
    int i;
    int tmpB;
    int tmpA;
    f32 frac;
    f32 ratio;
    f32 ds;
    f32 bestD;
    int msg0[3];
    int msgA[3];
    int msgB[3];
    int msgC[3];
    int cnt;

    *(u8 *)(sub + 0x15) &= ~4;
    *(u8 *)(sub + 0x14) |= 2;
    fn_80137948(tbl + 0x430, *(int *)(sub + 0x3c), *(int *)(sub + 0x18));
    if (*(void **)(sub + 0x3c) == NULL) {
        player = Obj_GetPlayerObject();
        q = *(int *)(sub + 0x24);
        msg0[0] = 0xf;
        msg0[1] = 1;
        msg0[2] = player;
        if (Stack_IsFull(q) == 0) {
            Stack_Push(q, msg0);
        }
        *(u8 *)(sub + 0x34) = 1;
        return 0;
    }
    if (*(s8 *)(p2 + 0x27a) != 0) {
        ObjAnim_SetCurrentMove(obj, 0x11, lbl_803E62A8, 0);
        *(u8 *)(p2 + 0x346) = 0;
    }
    *(f32 *)(p2 + 0x2a0) = lbl_803E6300;
    frac = (f32)*(u8 *)(blob + 0x406) / lbl_803E62B8;
    if (*(void **)(sub + 0x18) == NULL) {
        h = *(s16 *)(sub + 0x1c);
        if (h != -1) {
            tmpA = *(int *)(sub + 0x30);
            tmpB = *(int *)(sub + 0x2c);
            q = *(int *)(sub + 0x24);
            msgA[0] = *(int *)(sub + 0x28);
            msgA[1] = tmpB;
            msgA[2] = tmpA;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgA);
            }
            q = *(int *)(sub + 0x24);
            msgB[0] = 9;
            msgB[1] = 0;
            msgB[2] = h;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgB);
            }
            *(u8 *)(sub + 0x34) = 1;
            *(s16 *)(sub + 0x1c) = -1;
        }
    }
    if (((u32)*(u8 *)(sub + 0x44) >> 5 & 1) != 0) {
        fn_80202A2C(obj, (int *)(tbl + 0x344), (f32 *)(tbl + 0x354), 4, frac);
    }
    player = Obj_GetPlayerObject();
    ratio = (Vec_xzDistance(obj + 0x18, player + 0x18) - lbl_803E6304) / (lbl_803E6308 * (f32)*(u8 *)(blob + 0x406));
    n = (int)(ratio < lbl_803E62A8 ? lbl_803E62A8 : (ratio > lbl_803E62B0 ? lbl_803E62B0 : ratio));
    fn_80137948(tbl + 0x444, n);
    player = Obj_GetPlayerObject();
    best = 0;
    bestD = lbl_803E62A8;
    objs = ObjGroup_GetObjects(c30, &cnt);
    for (i = 0; i < cnt; i++) {
        o = *objs;
        if ((u32)o != (u32)player) {
            ds = vec3f_distanceSquared(player + 0x18, o + 0x18);
            if (ds > bestD) {
                bestD = ds;
                best = *objs;
            }
        }
        objs++;
    }
    if ((u32)best != 0) {
        sqrtf(bestD);
    }
    if ((u32)best != 0) {
        if ((u32)best != (u32)obj) {
            if (*(s16 *)(best + 0x46) == 0x539) {
                *(int *)(p2 + 0x2d0) = best;
                if (randomGetRange(0, n) == 0) {
                    if ((**(int (**)(int, int, int))(*(int *)(*(int *)(best + 0x68)) + 0x24))(best, 0x82, *(int *)(sub + 0x18)) != 0) {
                        *(int *)(sub + 0x3c) = 0;
                        q = *(int *)(sub + 0x24);
                        msgC[0] = 0xa;
                        msgC[1] = 1;
                        msgC[2] = best;
                        if (Stack_IsFull(q) == 0) {
                            Stack_Push(q, msgC);
                        }
                        *(u8 *)(sub + 0x34) = 1;
                    }
                } else {
                    fn_80202C78(obj, best, lbl_803E630C, frac, lbl_803E62CC, t);
                }
            }
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void chuka_update(int obj)
{
    extern int *ObjList_GetObjects(int *, int *);
    extern uint GameBit_Get(int);
    extern void Obj_SetActiveModelIndex(int, int);
    extern u8 gChukaModeTable[];
    extern f32 lbl_803E63F8;
    extern f32 lbl_803E63FC;
    int data = *(int *)(obj + 0x4c);
    int blob = *(int *)(obj + 0xb8);
    int ch;
    int *base;
    int i;
    int o;
    int h;
    int idx;
    int cnt;

    ch = *(int *)(blob + 4);
    if ((u32)ch != 0) {
        if (*(s16 *)(ch + 6) & 0x40) {
            *(int *)(blob + 4) = 0;
            return;
        }
    }
    if (*(void **)(blob + 4) == NULL) {
        base = ObjList_GetObjects(&idx, &cnt);
        for (i = idx; i < cnt; i++) {
            o = base[i];
            if (*(s16 *)(o + 0x46) == 0x431) {
                *(int *)(blob + 4) = o;
                i = cnt;
            }
        }
        if (*(void **)(blob + 4) == NULL) {
            return;
        }
    }
    ch = *(int *)(blob + 4);
    (**(void (**)(int, u8 *))(*(int *)(*(int *)(ch + 0x68)) + 0x20))(ch, gChukaModeTable);
    if (GameBit_Get(0x5e4) == 0) {
        *(u8 *)(blob + 9) = 0;
    } else {
        *(u8 *)(blob + 9) = gChukaModeTable[*(u8 *)(blob + 8)];
    }
    switch (*(u8 *)(blob + 9)) {
    case 0:
        if (*(s8 *)(obj + 0xad) != 0) {
            Obj_SetActiveModelIndex(obj, 0);
        }
        h = *(s16 *)(data + 0x1c);
        if (h != 0) {
            *(f32 *)(obj + 8) = lbl_803E63F8 / ((f32)h / lbl_803E63FC);
        }
        break;
    case 1:
        if (*(s8 *)(obj + 0xad) != 1) {
            Obj_SetActiveModelIndex(obj, 1);
        }
        h = *(s16 *)(data + 0x1c);
        if (h != 0) {
            *(f32 *)(obj + 8) = lbl_803E63F8 / ((f32)h / lbl_803E63FC);
        }
        if (*(s16 *)(obj + 4) != 0) {
            *(s16 *)(obj + 4) = 0;
        }
        break;
    case 2:
        if (*(s8 *)(obj + 0xad) != 2) {
            Obj_SetActiveModelIndex(obj, 2);
        }
        h = *(s16 *)(data + 0x1c);
        if (h != 0) {
            *(f32 *)(obj + 8) = lbl_803E63F8 / ((f32)h / lbl_803E63FC);
        }
        if (*(s16 *)(obj + 4) != 0) {
            *(s16 *)(obj + 4) = 0;
        }
        break;
    case 3:
        if (*(s8 *)(obj + 0xad) != 2) {
            Obj_SetActiveModelIndex(obj, 2);
        }
        h = *(s16 *)(data + 0x1c);
        if (h != 0) {
            *(f32 *)(obj + 8) = lbl_803E63F8 / ((f32)h / lbl_803E63FC);
        }
        if (*(s16 *)(obj + 4) != 0x3fff) {
            *(s16 *)(obj + 4) = 0x7fff;
        }
        break;
    case 4:
        if (*(s8 *)(obj + 0xad) != 1) {
            Obj_SetActiveModelIndex(obj, 1);
        }
        h = *(s16 *)(data + 0x1c);
        if (h != 0) {
            *(f32 *)(obj + 8) = lbl_803E63F8 / ((f32)h / lbl_803E63FC);
        }
        if (*(s16 *)(obj + 4) != 0x3fff) {
            *(s16 *)(obj + 4) = 0x7fff;
        }
        break;
    default:
        if (*(s8 *)(obj + 0xad) != 0) {
            Obj_SetActiveModelIndex(obj, 0);
        }
        h = *(s16 *)(data + 0x1c);
        if (h != 0) {
            *(f32 *)(obj + 8) = lbl_803E63F8 / ((f32)h / lbl_803E63FC);
        }
        if (*(s16 *)(obj + 4) != 0) {
            *(s16 *)(obj + 4) = 0;
        }
        break;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void DFP_Torch_update(int obj)
{
    extern void Sfx_PlayFromObject(int, int);
    extern void Sfx_StopObjectChannel(int, int);
    extern void objUpdateOpacity(int);
    extern int ObjHits_GetPriorityHit(int, int, int, int);
    extern int Resource_Acquire(int id, int flag);
    extern void Resource_Release(int);
    extern uint GameBit_Get(int);
    extern void GameBit_Set(int, int);
    extern int *gPartfxInterface;
    extern int *gModgfxInterface;
    extern int *gExpgfxInterface;
    extern u8 lbl_803DDCE8;
    extern f32 timeDelta;
    extern f32 lbl_803E63E0;
    extern int lbl_802C2510[];
    typedef struct {
        int m0;
        int m1;
        int m2;
        int m3;
    } TorchPrm;
    int blob = *(int *)(obj + 0xb8);
    int res;
    int h;
    int i;
    f32 buf[5];
    TorchPrm prm;

    prm = *(TorchPrm *)lbl_802C2510;
    Sfx_PlayFromObject(obj, 0x72);
    objUpdateOpacity(obj);
    switch (*(u8 *)(blob + 9)) {
    case 0:
        break;
    case 1:
        buf[4] = lbl_803E63E0;
        *(u8 *)(blob + 0xc) = *(u8 *)(blob + 0xa);
        if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0) {
            *(u8 *)(blob + 0xa) = 1 - *(u8 *)(blob + 0xa);
            if (*(u8 *)(blob + 0xa) != 0) {
                *(s16 *)(blob + 6) = 0x7d0;
            }
        }
        if (*(u8 *)(blob + 0xa) != 0) {
            h = *(s16 *)(blob + 6);
            if (h != 0) {
                *(s16 *)(blob + 6) = h - (int)timeDelta;
                if (*(s16 *)(blob + 6) <= 0) {
                    *(s16 *)(blob + 6) = 0;
                    *(u8 *)(blob + 0xa) = 0;
                }
            }
        }
        if (*(u8 *)(blob + 0xa) != 0 && *(s16 *)(blob + 4) <= 0 && *(u8 *)(blob + 0xb) != 0) {
            *(u8 *)(blob + 0xb) = 0;
            Sfx_PlayFromObject(obj, 0x80);
        }
        if (*(u8 *)(blob + 0xa) != *(u8 *)(blob + 0xc)) {
            if (*(u8 *)(blob + 0xa) != 0) {
                res = Resource_Acquire(0x69, 1);
                prm.m1 = *(u8 *)(blob + 0xd) * 2 + 0x19d;
                prm.m2 = *(u8 *)(blob + 0xd) * 2 + 0x19e;
                (*(void (*)(int, int, f32 *, int, int, void *))(*(int *)(*(int *)res + 4)))(obj, 1, buf, 0x10004, -1, &prm);
                Resource_Release(res);
                for (i = 0; i < 0x64; i++) {
                    (**(void (**)(int, int, int, int, int, int))((char *)*gPartfxInterface + 8))(obj, 0x1a3, 0, 0, -1, 0);
                }
                if (*(int *)blob != -1) {
                    if (GameBit_Get(*(int *)blob) == 0) {
                        GameBit_Set(*(int *)blob, 1);
                    }
                }
                if ((s8)lbl_803DDCE8 == 0 && *(u8 *)(blob + 0xd) == 0 && GameBit_Get(*(int *)blob) != 0) {
                    lbl_803DDCE8 = 1;
                }
                if ((s8)lbl_803DDCE8 == 1 && *(u8 *)(blob + 0xd) == 1 && GameBit_Get(*(int *)blob) != 0) {
                    GameBit_Set(0x5e2, 1);
                    lbl_803DDCE8 = 2;
                }
                *(u8 *)(blob + 0xb) = 1;
                *(s16 *)(blob + 4) = 1;
            } else {
                Sfx_StopObjectChannel(obj, 0x40);
                (**(void (**)(int))((char *)*gModgfxInterface + 0x18))(obj);
                (**(void (**)(int))((char *)*gExpgfxInterface + 0x14))(obj);
                if (*(int *)blob != -1) {
                    if (GameBit_Get(*(int *)blob) != 0) {
                        GameBit_Set(*(int *)blob, 0);
                    }
                }
                if ((s8)lbl_803DDCE8 == 1 && *(u8 *)(blob + 0xd) == 0) {
                    lbl_803DDCE8 = 0;
                }
                if ((s8)lbl_803DDCE8 == 2 && *(u8 *)(blob + 0xd) == 1 && GameBit_Get(0x5e2) == 0) {
                    GameBit_Set(0x5e2, 0);
                    lbl_803DDCE8 = 0;
                }
            }
        }
        break;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drakorenergy_update(int obj)
{
    extern int Obj_GetPlayerObject(void);
    extern uint GameBit_Get(int);
    extern void objMove(int, f32, f32, f32);
    extern f32 Vec_distance(int, int);
    extern f32 Vec_xzDistance(int, int);
    extern void playerAddHealth(int, int);
    extern void Sfx_PlayFromObject(int, int);
    extern f32 fn_80293E80(f32);
    extern void fn_80221C18(int, int, f32 *, f32);
    extern void PSVECSubtract(f32 *, f32 *, f32 *);
    extern void PSVECNormalize(f32 *, f32 *);
    extern void PSVECScale(f32 *, f32 *, f32);
    extern void objfx_spawnFlaggedTrailBurst(int, f32, int, int, int, int);
    extern int *gPartfxInterface;
    extern f32 timeDelta;
    extern u8 framesThisStep;
    extern f32 lbl_803E627C;
    extern f32 lbl_803E6280;
    extern f32 lbl_803E6284;
    extern f32 lbl_803E6288;
    extern f32 lbl_803E628C;
    extern f32 lbl_803E6290;
    extern f32 lbl_803E6294;
    extern f32 lbl_803DC160;
    extern f32 lbl_803DC164;
    extern f32 lbl_803DC168;
    extern f32 lbl_803DC16C;
    extern int lbl_803DC170;
    extern f32 lbl_803DC174;
    extern s16 lbl_803DC178;
    int blob = *(int *)(obj + 0xb8);
    int data;
    int player;
    f32 v;
    f32 dist;
    f32 spd;
    f32 v1[3];
    f32 v2[3];
    s16 trio[12];

    player = Obj_GetPlayerObject();
    data = *(int *)(obj + 0x4c);
    switch (*(u8 *)(blob + 8)) {
    case 0:
        if (GameBit_Get(*(s16 *)(data + 0x20)) == 1) {
            *(u8 *)(blob + 8) = 2;
        }
        break;
    case 1:
        if (*(f32 *)blob - *(f32 *)(obj + 0x10) > (v = lbl_803E627C)) {
            *(f32 *)(obj + 0x28) = lbl_803E6280 * -*(f32 *)(obj + 0x28);
            dist = *(f32 *)(obj + 0x28);
            dist = dist >= v ? -dist : dist;
            if (dist < lbl_803E6284) {
                *(u8 *)(blob + 8) = 2;
                *(f32 *)(obj + 0x24) = lbl_803E627C;
                *(f32 *)(obj + 0x2c) = lbl_803E627C;
                break;
            }
        }
        *(f32 *)(obj + 0x28) += lbl_803E6288;
        objMove(obj, *(f32 *)(obj + 0x24), *(f32 *)(obj + 0x28), *(f32 *)(obj + 0x2c));
        trio[2] = 0xff;
        trio[1] = 0xff - *(int *)(blob + 4) % 0x500;
        trio[0] = 0xff;
        (**(void (**)(int, int, s16 *, int, int, int))((char *)*gPartfxInterface + 8))(obj, 0x357, trio, 0, -1, 0);
        break;
    case 2:
        *(f32 *)(obj + 0x28) = lbl_803DC160 * fn_80293E80(lbl_803E628C * (f32)*(int *)(blob + 4) / lbl_803E6290);
        objMove(obj, *(f32 *)(obj + 0x24), *(f32 *)(obj + 0x28), *(f32 *)(obj + 0x2c));
        if (Vec_distance(obj + 0x18, player + 0x18) < lbl_803DC164) {
            *(u8 *)(blob + 8) = 3;
        }
        objfx_spawnFlaggedTrailBurst(obj, lbl_803DC174, 1, 0xc22, 0x14, obj + 0x24);
        break;
    case 3:
        dist = Vec_xzDistance(obj + 0x18, player + 0x18);
        if (dist < lbl_803DC168) {
            playerAddHealth(player, lbl_803DC170);
            Sfx_PlayFromObject(obj, 0x49);
            *(u8 *)(blob + 8) = 4;
        } else {
            spd = lbl_803DC16C;
            fn_80221C18(player, obj + 0xc, v1, spd / lbl_803E6294);
            PSVECSubtract(v1, (f32 *)(obj + 0xc), v2);
            PSVECNormalize(v2, v2);
            if (dist < spd) {
                spd = dist;
            }
            PSVECScale(v2, (f32 *)(obj + 0x24), spd);
            objMove(obj, *(f32 *)(obj + 0x24) * timeDelta, *(f32 *)(obj + 0x28) * timeDelta, *(f32 *)(obj + 0x2c) * timeDelta);
            trio[2] = 0xff;
            trio[1] = 0;
            trio[0] = 0xff;
            objfx_spawnFlaggedTrailBurst(obj, lbl_803DC174, 1, 0xc22, 0x14, obj + 0x24);
        }
        break;
    case 5:
        *(u8 *)(blob + 8) = 0;
        break;
    }
    *(s16 *)obj += lbl_803DC178;
    *(int *)(blob + 4) += framesThisStep * 0x500;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int dfpseqpoint_SeqFn(int obj, int p2, int p3)
{
    extern void unlockLevel(int a, int b, int c);
    extern int mapGetDirIdx(int);
    extern void lockLevel(int, int);
    extern void warpToMap(int, int);
    extern int *gMapEventInterface;
    int blob = *(int *)(obj + 0xb8);
    int data = *(int *)(obj + 0x4c);
    int i;

    *(s16 *)(p3 + 0x70) = -1;
    *(u8 *)(p3 + 0x56) = 0;
    for (i = 0; i < *(u8 *)(p3 + 0x8b); i++) {
        switch (*(s16 *)(blob + 8)) {
        case 1:
            if (*(u8 *)(p3 + i + 0x81) == 1) {
                if ((u8)(**(int (**)(int))((char *)*(int *)gMapEventInterface + 0x40))(*(s8 *)(obj + 0xac)) == 1) {
                    (**(void (**)(int, int, int))((char *)*(int *)gMapEventInterface + 0x50))(*(s8 *)(obj + 0xac), 5, 0);
                    (**(void (**)(int, int, int))((char *)*(int *)gMapEventInterface + 0x50))(*(s8 *)(obj + 0xac), 6, 0);
                    (**(void (**)(int, int, int))((char *)*(int *)gMapEventInterface + 0x50))(*(s8 *)(obj + 0xac), 7, 0);
                } else if ((u8)(**(int (**)(int))((char *)*(int *)gMapEventInterface + 0x40))(*(s8 *)(obj + 0xac)) == 2) {
                    (**(void (**)(int, int, int))((char *)*(int *)gMapEventInterface + 0x50))(*(s8 *)(obj + 0xac), 5, 0);
                    (**(void (**)(int, int, int))((char *)*(int *)gMapEventInterface + 0x50))(*(s8 *)(obj + 0xac), 6, 0);
                    (**(void (**)(int, int, int))((char *)*(int *)gMapEventInterface + 0x50))(*(s8 *)(obj + 0xac), 7, 0);
                }
            }
            break;
        case 0xa:
            if (*(u8 *)(p3 + i + 0x81) == 0x14) {
                if (*(u32 *)(data + 0x14) == 0x49de8) {
                    ((DfpFlags7 *)(blob + 0xf))->b80 = 1;
                } else {
                    if ((u8)(**(int (**)(int))((char *)*(int *)gMapEventInterface + 0x40))(*(s8 *)(obj + 0xac)) == 1 ||
                        (u8)(**(int (**)(int))((char *)*(int *)gMapEventInterface + 0x40))(*(s8 *)(obj + 0xac)) == 2) {
                        unlockLevel(0, 0, 1);
                        lockLevel(mapGetDirIdx(0x32), 0);
                        (**(void (**)(int, int))((char *)*(int *)gMapEventInterface + 0x44))(0x32, 2);
                        warpToMap(0x73, 0);
                    }
                }
            }
            break;
        }
        *(u8 *)(p3 + i + 0x81) = 0;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void dfpseqpoint_update(int obj)
{
    extern int Obj_GetPlayerObject(void);
    extern uint GameBit_Get(int);
    extern void GameBit_Set(int, int);
    extern f32 Vec_distance(int, int);
    extern int *gObjectTriggerInterface;
    int player;
    int blob;
    int h;

    player = Obj_GetPlayerObject();
    blob = *(int *)(obj + 0xb8);
    if (((u32)*(u8 *)(blob + 0xf) >> 7 & 1) != 0) {
        GameBit_Set(0xef7, 1);
        ((DfpFlags7 *)(blob + 0xf))->b80 = 0;
    }
    h = *(s16 *)(blob + 6);
    if (h != -1) {
        if (*(u8 *)(blob + 0xd) != 0) {
            if (GameBit_Get(h) != 0) {
                return;
            }
            GameBit_Set(*(s16 *)(blob + 6), 1);
            *(u8 *)(blob + 0xd) = 1;
            return;
        }
        if (GameBit_Get(h) != 0) {
            *(u8 *)(blob + 0xd) = 1;
            return;
        }
    }
    if (*(u8 *)(blob + 0xd) != 0) {
        return;
    }
    switch (*(u8 *)(blob + 0xe)) {
    case 0:
        if (Vec_distance(obj + 0x18, player + 0x18) < *(f32 *)blob) {
            ((void (*)(int, int, int))((void **)*(int *)gObjectTriggerInterface)[18])(*(s16 *)(blob + 8), obj, -1);
            *(u8 *)(blob + 0xd) = 1;
        }
        break;
    case 1:
        h = *(s16 *)(blob + 4);
        if (h != -1 && GameBit_Get(h) != 0) {
            ((void (*)(int, int, int))((void **)*(int *)gObjectTriggerInterface)[18])(*(s16 *)(blob + 8), obj, -1);
            *(u8 *)(blob + 0xd) = 1;
        }
        break;
    case 2:
        if (Vec_distance(obj + 0x18, player + 0x18) < *(f32 *)blob) {
            h = *(s16 *)(blob + 4);
            if (h != -1 && GameBit_Get(h) != 0) {
                ((void (*)(int, int, int))((void **)*(int *)gObjectTriggerInterface)[18])(*(s16 *)(blob + 8), obj, -1);
                *(u8 *)(blob + 0xd) = 1;
            }
        }
        break;
    case 3:
        if (Vec_distance(obj + 0x18, player + 0x18) < *(f32 *)blob) {
            h = *(s16 *)(blob + 4);
            if (h != -1 && GameBit_Get(h) == 0) {
                ((void (*)(int, int, int))((void **)*(int *)gObjectTriggerInterface)[18])(*(s16 *)(blob + 8), obj, -1);
                GameBit_Set(*(s16 *)(blob + 4), 1);
                *(u8 *)(blob + 0xd) = 1;
            }
        }
        break;
    case 4:
        h = *(s16 *)(blob + 4);
        if (h != -1 && GameBit_Get(h) == 0) {
            ((void (*)(int, int, int))((void **)*(int *)gObjectTriggerInterface)[18])(*(s16 *)(blob + 8), obj, -1);
            GameBit_Set(*(s16 *)(blob + 4), 1);
            *(u8 *)(blob + 0xd) = 1;
        }
        break;
    case 5:
        h = *(s16 *)(blob + 4);
        if (h != -1 && GameBit_Get(h) != 0) {
            ((void (*)(int, int, int))((void **)*(int *)gObjectTriggerInterface)[18])(*(s16 *)(blob + 8), obj, -1);
        }
        break;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802004B0(int obj, int p2, f32 t)
{
    extern int Stack_IsFull(int sp);
    extern void Stack_Push(int sp, int *args);
    extern void ObjAnim_SampleRootCurvePhase(int, f32, int);
    extern f32 Vec_xzDistance(int, int);
    extern int randomGetRange(int, int);
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E62C0;
    extern f32 lbl_803E62C4;
    extern f32 lbl_803E62C8;
    extern f32 lbl_803E62CC;
    extern f32 lbl_803E62D0;
    extern f32 lbl_803E62D4;
    extern f32 lbl_803E62D8;
    extern int lbl_8032973C[];
    extern f32 lbl_8032974C[];
    int blob = *(int *)(obj + 0xb8);
    int sub = *(int *)(blob + 0x40c);
    int n = 0x1f40 / *(u8 *)(blob + 0x406);
    int tmpA;
    int tmpB;
    int q;
    int target;
    f32 frac;
    f32 d;
    int msgA[3];
    int msgB[3];
    int msgC[3];
    int msgD[3];

    *(u8 *)(sub + 0x14) |= 2;
    *(u8 *)(sub + 0x15) &= ~4;
    if (*(u16 *)(*(int *)(p2 + 0x2d0) + 0xb0) & 0x1000) {
        *(f32 *)(p2 + 0x280) = lbl_803E62A8;
        *(f32 *)(p2 + 0x284) = lbl_803E62A8;
        *(f32 *)(p2 + 0x2a0) = lbl_803E62C0;
        return 0;
    }
    frac = (f32)*(u8 *)(blob + 0x406) / lbl_803E62C4;
    fn_80202C78(obj, *(int *)(p2 + 0x2d0), lbl_803E62C8, frac, lbl_803E62CC, t);
    if (((u32)*(u8 *)(sub + 0x44) >> 5 & 1) != 0) {
        fn_80202A2C(obj, lbl_8032973C, lbl_8032974C, 4, frac);
    }
    d = Vec_xzDistance(obj + 0x18, *(int *)(p2 + 0x2d0) + 0x18);
    *(u8 *)(p2 + 0x34d) = 1;
    if (d < lbl_803E62D0) {
        *(f32 *)(p2 + 0x280) *= lbl_803E62D4;
        *(f32 *)(p2 + 0x284) *= lbl_803E62D4;
        target = *(int *)(p2 + 0x2d0);
        tmpA = *(int *)(sub + 0x30);
        tmpB = *(int *)(sub + 0x2c);
        q = *(int *)(sub + 0x24);
        msgA[0] = *(int *)(sub + 0x28);
        msgA[1] = tmpB;
        msgA[2] = tmpA;
        if (Stack_IsFull(q) == 0) {
            Stack_Push(q, msgA);
        }
        q = *(int *)(sub + 0x24);
        msgB[0] = 2;
        msgB[1] = 1;
        msgB[2] = target;
        if (Stack_IsFull(q) == 0) {
            Stack_Push(q, msgB);
        }
        *(u8 *)(sub + 0x34) = 1;
        return 0;
    }
    if (d < lbl_803E62D8 && randomGetRange(0, n) == 0) {
        *(f32 *)(p2 + 0x280) = lbl_803E62A8;
        *(f32 *)(p2 + 0x284) = lbl_803E62A8;
        target = *(int *)(p2 + 0x2d0);
        tmpA = *(int *)(sub + 0x30);
        tmpB = *(int *)(sub + 0x2c);
        q = *(int *)(sub + 0x24);
        msgC[0] = *(int *)(sub + 0x28);
        msgC[1] = tmpB;
        msgC[2] = tmpA;
        if (Stack_IsFull(q) == 0) {
            Stack_Push(q, msgC);
        }
        q = *(int *)(sub + 0x24);
        msgD[0] = 4;
        msgD[1] = 1;
        msgD[2] = target;
        if (Stack_IsFull(q) == 0) {
            Stack_Push(q, msgD);
        }
        *(u8 *)(sub + 0x34) = 1;
        return 0;
    }
    ObjAnim_SampleRootCurvePhase(obj, *(f32 *)(p2 + 0x280), p2 + 0x2a0);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void dbegg_update(int obj)
{
    extern int Obj_GetPlayerObject(void);
    extern int objPosToMapBlockIdx(f32, f32, f32);
    extern void dbegg_processMessages(int);
    extern int fn_801FE560(int, f32 *, f32, f32, int);
    extern void fn_801FE774(int, f32 *);
    extern void objMove(int, f32, f32, f32);
    extern void Sfx_PlayFromObject(int, int);
    extern void Sfx_KeepAliveLoopedObjectSound(int, int);
    extern uint GameBit_Get(int);
    extern void GameBit_Set(int, int);
    extern int randomGetRange(int, int);
    extern f32 Vec_xzDistance(int, int);
    extern void ObjGroup_RemoveObject(int, int);
    extern void ObjGroup_AddObject(int, int);
    extern void ObjMsg_SendToObject(int, int, int, int);
    extern uint getButtonsJustPressed(int);
    extern int Curve_AdvanceAlongPath(int, f32);
    extern f32 sqrtf(f32);
    extern void Vec3_Normalize(int);
    extern f32 PSVECMag(int);
    extern void fn_80137948(char *, ...);
    extern void ObjHits_EnableObject(int);
    extern void ObjHits_DisableObject(int);
    extern int *gWaterfxInterface;
    extern int *gRomCurveInterface;
    extern int *gPartfxInterface;
    extern f32 timeDelta;
    extern f32 oneOverTimeDelta;
    extern char sAnimGreaterMessage[];
    extern int lbl_803E61C0;
    extern int lbl_803E61C4;
    extern f32 lbl_803E61C8;
    extern f32 lbl_803E61CC;
    extern f32 lbl_803E61E4;
    extern f32 lbl_803E61EC;
    extern f32 lbl_803E6200;
    extern f32 lbl_803E6220;
    extern f32 lbl_803E6224;
    extern f32 lbl_803E6228;
    extern f32 lbl_803E622C;
    extern f32 lbl_803E6230;
    extern f32 lbl_803E6234;
    extern f32 lbl_803E6238;
    extern f32 lbl_803E623C;
    extern f32 lbl_803E6240;
    extern f32 lbl_803E6244;
    extern f32 lbl_803E6248;
    extern f32 lbl_803E624C;
    extern f32 lbl_803E6250;
    extern f32 lbl_803E6254;
    extern f32 lbl_803E6258;
    extern f32 lbl_803E625C;
    extern f32 lbl_803E6260;
    extern f32 lbl_803E6264;
    extern f32 lbl_803E6268;
    int data = *(int *)(obj + 0x4c);
    int player;
    int blob;
    int p2;
    int b2;
    int d2;
    int n;
    int i;
    f32 v;
    f32 fx;
    f32 fz;
    f32 b3[3];
    f32 d[3];
    int buf2[2];
    f32 h;

    player = Obj_GetPlayerObject();
    blob = *(int *)(obj + 0xb8);
    n = lbl_803E61C0;
    i = lbl_803E61C4;
    buf2[1] = i;
    buf2[0] = n;
    if (objPosToMapBlockIdx(*(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14)) != -1) {
        dbegg_processMessages(obj);
        *(s16 *)(*(int *)(obj + 0x54) + 0x60) &= ~0x400;
        switch (*(u8 *)(blob + 0x118)) {
        case 5:
            if (*(int *)(obj + 0xf8) == 0) {
                *(s16 *)(*(int *)(obj + 0x54) + 0x60) |= 1;
            }
            if (fn_801FE560(obj, &h, lbl_803E61C8, lbl_803E61C8, 1) == 0) {
                *(u8 *)(blob + 0x118) = 2;
                break;
            }
            v = h;
            v = v >= lbl_803E61C8 ? v : -v;
            if (v < lbl_803E6220) {
                if (*(u8 *)(blob + 0x119) & 0x10) {
                    *(u8 *)(blob + 0x118) = 0xd;
                } else {
                    *(u8 *)(blob + 0x118) = 1;
                }
                fz = lbl_803E61C8;
                *(f32 *)(obj + 0x24) = lbl_803E61C8;
                *(f32 *)(obj + 0x2c) = fz;
                *(f32 *)(obj + 0x28) = fz;
                *(f32 *)(obj + 0x10) = *(f32 *)(obj + 0x10) + h;
            } else {
                *(f32 *)(obj + 0x28) += lbl_803E6224;
                if (h > lbl_803E61C8) {
                    *(f32 *)(obj + 0x28) = lbl_803E6228 * -*(f32 *)(obj + 0x28);
                    *(f32 *)(obj + 0x24) = *(f32 *)(obj + 0x24) * lbl_803E622C;
                    *(f32 *)(obj + 0x2c) = *(f32 *)(obj + 0x2c) * lbl_803E622C;
                    v = *(f32 *)(obj + 0x28);
                    v = v >= lbl_803E61C8 ? v : -v;
                    if (v > lbl_803E6230) {
                        Sfx_PlayFromObject(obj, 0x2df);
                    }
                }
                objMove(obj, *(f32 *)(obj + 0x24) * timeDelta, *(f32 *)(obj + 0x28) * timeDelta, *(f32 *)(obj + 0x2c) * timeDelta);
                *(u8 *)(obj + 0xaf) |= 8;
            }
            break;
        case 1:
            if (*(int *)(obj + 0xf8) == 0) {
                *(s16 *)(*(int *)(obj + 0x54) + 0x60) |= 1;
            }
            *(u8 *)(obj + 0xaf) &= ~8;
            break;
        case 2:
            if (*(u8 *)(blob + 0x119) & 4) {
                *(u8 *)(obj + 0xaf) |= 8;
                *(f32 *)(obj + 0x24) = *(f32 *)(obj + 0x24) + (*(f32 *)(data + 8) - *(f32 *)(obj + 0xc)) / (fz = lbl_803E61E4);
                *(f32 *)(obj + 0x28) = *(f32 *)(obj + 0x28) + (*(f32 *)(data + 0xc) - *(f32 *)(obj + 0x10)) / fz;
                *(f32 *)(obj + 0x2c) = *(f32 *)(obj + 0x2c) + (*(f32 *)(data + 0x10) - *(f32 *)(obj + 0x14)) / fz;
                if (GameBit_Get(0x44d) != 0) {
                    *(u8 *)(blob + 0x118) = 0xa;
                }
            }
            *(s16 *)(*(int *)(obj + 0x54) + 0x60) |= 0x400;
            fz = lbl_803E61C8;
            b3[0] = lbl_803E61C8;
            b3[1] = fz;
            b3[2] = fz;
            fn_801FE774(obj, b3);
            *(f32 *)(obj + 0x24) = *(f32 *)(obj + 0x24) + b3[0];
            *(f32 *)(obj + 0x28) = *(f32 *)(obj + 0x28) + b3[1];
            *(f32 *)(obj + 0x2c) = *(f32 *)(obj + 0x2c) + b3[2];
            if (fn_801FE560(obj, &h, *(f32 *)(obj + 0x24) * timeDelta, *(f32 *)(obj + 0x2c) * timeDelta, 1) != 0) {
                *(f32 *)(obj + 0x24) = lbl_803E6234 * *(f32 *)(obj + 0x24);
                *(f32 *)(obj + 0x2c) = lbl_803E6234 * *(f32 *)(obj + 0x2c);
                fn_801FE560(obj, &h, *(f32 *)(obj + 0x24) * timeDelta, *(f32 *)(obj + 0x2c) * timeDelta, 1);
            }
            h = h + *(f32 *)blob;
            if (oneOverTimeDelta != lbl_803E61C8) {
                *(f32 *)(obj + 0x28) = h * (lbl_803E6238 * oneOverTimeDelta);
            } else {
                *(f32 *)(obj + 0x28) = lbl_803E61C8;
            }
            randomGetRange(0x64, 0x1388);
            randomGetRange(0x64, 0x1388);
            objMove(obj, *(f32 *)(obj + 0x24) * timeDelta, *(f32 *)(obj + 0x28) * timeDelta, *(f32 *)(obj + 0x2c) * timeDelta);
            if (randomGetRange(0, 10) == 0 && ((h < lbl_803E6200) < 0 ? -(h < lbl_803E6200) : (h < lbl_803E6200))) {
                (**(void (**)(int, int, f32, f32, f32, f32))((char *)*gWaterfxInterface + 0x14))(*(s16 *)obj, 1, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10) - *(f32 *)blob, *(f32 *)(obj + 0x14), (f32)randomGetRange(1, 10));
            }
            if (GameBit_Get(0x426) != 0) {
                *(u8 *)(obj + 0xaf) &= ~8;
                *(f32 *)blob = *(f32 *)blob - lbl_803E623C * timeDelta;
                if (*(f32 *)blob < lbl_803E61EC) {
                    GameBit_Set(0x428, GameBit_Get(0x428) + 1);
                    *(u8 *)(blob + 0x118) = 7;
                    fz = lbl_803E61C8;
                    *(f32 *)(obj + 0x28) = lbl_803E61C8;
                    *(f32 *)(obj + 0x24) = fz;
                    *(f32 *)(obj + 0x2c) = fz;
                    *(u8 *)(obj + 0xaf) |= 8;
                }
            } else if (*(u8 *)(blob + 0x119) & 2) {
                *(u8 *)(obj + 0xaf) |= 8;
            }
            break;
        case 4:
            *(u8 *)(obj + 0xaf) |= 8;
            break;
        case 6:
            if (Vec_xzDistance(obj + 0x18, data + 8) > lbl_803E6240 && (*(u8 *)(blob + 0x119) & 2) == 0) {
                p2 = Obj_GetPlayerObject();
                b2 = *(int *)(obj + 0xb8);
                d2 = *(int *)(obj + 0x4c);
                ObjGroup_RemoveObject(obj, 0x24);
                *(u8 *)(b2 + 0x118) = 3;
                GameBit_Set(0x3c4, 1);
                GameBit_Set(0x86d, 1);
                *(u8 *)(obj + 0xaf) |= 8;
                GameBit_Set(*(s16 *)(d2 + 0x1c), 1);
                *(s16 *)(b2 + 0x11c) = -1;
                *(s16 *)(b2 + 0x11e) = 0;
                *(f32 *)(b2 + 0x120) = lbl_803E61CC;
                ObjMsg_SendToObject(p2, 0x7000a, obj, b2 + 0x11c);
                *(int *)(obj + 0xf8) = 0;
            } else if (getButtonsJustPressed(0) & 0x100) {
                *(u8 *)(blob + 0x118) = 5;
                *(u8 *)(obj + 0xaf) &= ~8;
            } else {
                *(s16 *)(*(int *)(obj + 0x54) + 0x60) &= ~1;
                ObjMsg_SendToObject(player, 0x100008, obj, 0x38000);
                *(u8 *)(obj + 0xaf) |= 8;
            }
            break;
        case 0xb:
            *(u8 *)(obj + 0xaf) |= 8;
            return;
        case 7:
            fn_801FE560(obj, &h, lbl_803E61C8, lbl_803E61C8, 0);
            v = h;
            v = v >= lbl_803E61C8 ? v : -v;
            if (v < lbl_803E6220) {
                *(u8 *)(blob + 0x118) = 8;
                fz = lbl_803E61C8;
                *(f32 *)(obj + 0x24) = lbl_803E61C8;
                *(f32 *)(obj + 0x2c) = fz;
            } else {
                *(f32 *)(obj + 0x28) += lbl_803E6244;
                if (h > lbl_803E61C8) {
                    *(f32 *)(obj + 0x28) = lbl_803E6248 * -*(f32 *)(obj + 0x28);
                }
                objMove(obj, *(f32 *)(obj + 0x24) * timeDelta, *(f32 *)(obj + 0x28) * timeDelta, *(f32 *)(obj + 0x2c) * timeDelta);
            }
            break;
        case 8:
            if (GameBit_Get(0x42a) != 0) {
                dbegg_setupFromDef(obj, (int *)blob);
            } else if (randomGetRange(0, 10) == 0) {
                (**(void (**)(int, int, int, int, int, int))((char *)*gPartfxInterface + 8))(obj, 0x3be, 0, 0, -1, 0);
            }
            break;
        case 0xa:
            if ((u8)(**(int (**)(int, int, f32, int *, int))((char *)*gRomCurveInterface + 0x8c))(blob + 4, obj, lbl_803E624C, buf2, 2) != 0) {
                *(u8 *)(blob + 0x118) = 5;
            } else {
                *(u8 *)(obj + 0xaf) &= ~8;
                *(u8 *)(blob + 0x118) = 9;
                n = *(u8 *)(blob + 0x119);
                if (n & 4) {
                    *(u8 *)(blob + 0x119) = n & ~4;
                }
            }
            break;
        case 9:
            if (Curve_AdvanceAlongPath(blob + 4, lbl_803E6250) != 0 || *(int *)(blob + 0x14) != 0) {
                if ((u8)(**(int (**)(int))((char *)*gRomCurveInterface + 0x90))(blob + 4) != 0) {
                    *(u8 *)(blob + 0x118) = 5;
                }
            } else {
                *(f32 *)(obj + 0x24) = *(f32 *)(blob + 0x6c) - *(f32 *)(obj + 0xc);
                *(f32 *)(obj + 0x28) = *(f32 *)(blob + 0x70) - *(f32 *)(obj + 0x10);
                *(f32 *)(obj + 0x2c) = *(f32 *)(blob + 0x74) - *(f32 *)(obj + 0x14);
                fx = sqrtf(*(f32 *)(obj + 0x2c) * *(f32 *)(obj + 0x2c) + (*(f32 *)(obj + 0x24) * *(f32 *)(obj + 0x24) + *(f32 *)(obj + 0x28) * *(f32 *)(obj + 0x28)));
                if (fx > lbl_803E6254 * timeDelta) {
                    Vec3_Normalize(obj + 0x24);
                    *(f32 *)(obj + 0x24) = *(f32 *)(obj + 0x24) * (lbl_803E6254 * timeDelta);
                    *(f32 *)(obj + 0x28) = *(f32 *)(obj + 0x28) * (lbl_803E6254 * timeDelta);
                    *(f32 *)(obj + 0x2c) = *(f32 *)(obj + 0x2c) * (lbl_803E6254 * timeDelta);
                    fn_80137948(sAnimGreaterMessage);
                }
                *(f32 *)(obj + 0xc) = *(f32 *)(obj + 0xc) + *(f32 *)(obj + 0x24);
                *(f32 *)(obj + 0x10) = *(f32 *)(obj + 0x10) + *(f32 *)(obj + 0x28);
                *(f32 *)(obj + 0x14) = *(f32 *)(obj + 0x14) + *(f32 *)(obj + 0x2c);
            }
            break;
        case 0xc:
            if (GameBit_Get(*(s16 *)(data + 0x24)) != 0) {
                ObjGroup_AddObject(obj, 0x24);
                *(u8 *)(blob + 0x118) = 5;
            }
            break;
        case 0xd:
            ObjHits_DisableObject(obj);
            *(f32 *)(obj + 0x24) = *(f32 *)(obj + 0x24) + (*(f32 *)(data + 8) - *(f32 *)(obj + 0xc)) / (fz = lbl_803E6258);
            *(f32 *)(obj + 0x28) = *(f32 *)(obj + 0x28) + (*(f32 *)(data + 0xc) - *(f32 *)(obj + 0x10)) / fz;
            *(f32 *)(obj + 0x2c) = *(f32 *)(obj + 0x2c) + (*(f32 *)(data + 0x10) - *(f32 *)(obj + 0x14)) / fz;
            d[0] = *(f32 *)(obj + 0xc) - *(f32 *)(data + 8);
            d[1] = *(f32 *)(obj + 0x10) - *(f32 *)(data + 0xc);
            d[2] = *(f32 *)(obj + 0x14) - *(f32 *)(data + 0x10);
            Sfx_KeepAliveLoopedObjectSound(obj, 0x442);
            fz = d[2];
            fz = fz >= lbl_803E61C8 ? fz : -fz;
            fx = d[0];
            fx = fx >= lbl_803E61C8 ? fx : -fx;
            if (fx + fz < lbl_803E625C) {
                ObjHits_EnableObject(obj);
                *(u8 *)(blob + 0x118) = 1;
                *(f32 *)(obj + 0xc) = *(f32 *)(data + 8);
                *(f32 *)(obj + 0x10) = *(f32 *)(data + 0xc);
                *(f32 *)(obj + 0x14) = *(f32 *)(data + 0x10);
            } else {
                n = (int)(PSVECMag(obj + 0x24) / lbl_803E6260);
                for (i = 0; i < n; i++) {
                    (**(void (**)(int, int, int, int, int, int))((char *)*gPartfxInterface + 8))(obj, 0x345, 0, 1, -1, 0);
                }
                objMove(obj, *(f32 *)(obj + 0x24) * timeDelta, *(f32 *)(obj + 0x28) * timeDelta, *(f32 *)(obj + 0x2c) * timeDelta);
            }
            break;
        }
        if (*(u8 *)(blob + 0x119) & 8) {
            *(u8 *)(obj + 0xaf) |= 8;
            ObjHits_DisableObject(obj);
            if (GameBit_Get(*(s16 *)(data + 0x1c)) != 0) {
                *(u8 *)(blob + 0x119) &= ~9;
                *(u8 *)(obj + 0xaf) &= ~8;
                ObjHits_EnableObject(obj);
            }
        } else if (*(u8 *)(obj + 0xaf) & 1) {
            if (GameBit_Get(0x3c4) == 0) {
                if (Vec_xzDistance(obj + 0x18, player + 0x18) < lbl_803E6264) {
                    if ((*(u8 *)(blob + 0x119) & 1) == 0) {
                        p2 = Obj_GetPlayerObject();
                        b2 = *(int *)(obj + 0xb8);
                        d2 = *(int *)(obj + 0x4c);
                        ObjGroup_RemoveObject(obj, 0x24);
                        *(u8 *)(b2 + 0x118) = 3;
                        GameBit_Set(0x3c4, 1);
                        GameBit_Set(0x86d, 1);
                        *(u8 *)(obj + 0xaf) |= 8;
                        GameBit_Set(*(s16 *)(d2 + 0x1c), 1);
                        *(s16 *)(b2 + 0x11c) = -1;
                        *(s16 *)(b2 + 0x11e) = 0;
                        *(f32 *)(b2 + 0x120) = lbl_803E61CC;
                        ObjMsg_SendToObject(p2, 0x7000a, obj, b2 + 0x11c);
                    } else {
                        v = *(f32 *)(obj + 0x10) - *(f32 *)(player + 0x10);
                        v = v >= lbl_803E61C8 ? v : -v;
                        if (v < lbl_803E6268) {
                            *(u8 *)(obj + 0xaf) |= 8;
                            *(u8 *)(blob + 0x118) = 6;
                            *(s16 *)(*(int *)(obj + 0x54) + 0x60) &= ~1;
                        }
                    }
                }
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
