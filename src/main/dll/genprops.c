#include "ghidra_import.h"
#include "main/dll/genprops.h"

extern undefined4 FUN_80003494();
extern undefined4 FUN_800067e8();
extern undefined8 FUN_8000680c();
extern undefined4 FUN_80006810();
extern undefined4 FUN_80006818();
extern undefined4 FUN_80006820();
extern undefined8 FUN_80006824();
extern undefined4 FUN_800068c8();
extern undefined8 FUN_8000691c();
extern void* FUN_80006974();
extern double FUN_80006a38();
extern undefined4 FUN_80006b0c();
extern int FUN_80006b14();
extern undefined4 FUN_8001753c();
extern undefined4 FUN_80017544();
extern undefined4 FUN_8001754c();
extern undefined4 FUN_80017588();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175a0();
extern undefined4 FUN_800175b0();
extern undefined4 FUN_800175bc();
extern undefined4 FUN_800175cc();
extern undefined4 FUN_800175d0();
extern undefined4 FUN_800175d8();
extern undefined4 FUN_800175ec();
extern undefined4 FUN_80017620();
extern void* FUN_80017624();
extern undefined4 FUN_80017688();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern int FUN_800176d0();
extern double FUN_80017714();
extern undefined4 FUN_80017730();
extern undefined4 FUN_80017748();
extern undefined4 FUN_80017754();
extern uint FUN_80017760();
extern undefined4 FUN_80017778();
extern undefined4 FUN_8001778c();
extern undefined4 FUN_80017814();
extern int FUN_80017830();
extern undefined4 FUN_80017954();
extern undefined4 FUN_80017958();
extern undefined4 FUN_80017a0c();
extern undefined4 FUN_80017a50();
extern int FUN_80017a54();
extern int FUN_80017a5c();
extern undefined4 FUN_80017a78();
extern undefined4 FUN_80017a7c();
extern undefined4 FUN_80017a88();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 FUN_80017b00();
extern undefined8 FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_SetTargetMask();
extern undefined4 FUN_80035b84();
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined8 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHitWithPosition();
extern undefined4 ObjGroup_FindNearestObject();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined8 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();
extern uint FUN_80038b0c();
extern undefined4 FUN_8003b540();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8004036c();
extern undefined4 FUN_80040a88();
extern undefined4 FUN_8004812c();
extern undefined4 FUN_80053754();
extern undefined4 FUN_80053758();
extern undefined4 FUN_80053ba4();
extern undefined4 FUN_80053bb0();
extern undefined4 FUN_8005fe14();
extern undefined4 FUN_80061194();
extern undefined4 FUN_800632d8();
extern int FUN_800632e8();
extern undefined4 FUN_8006f8a4();
extern undefined4 FUN_8006f8fc();
extern undefined4 FUN_8006fb18();
extern undefined4 FUN_80071e78();
extern undefined4 FUN_80071f8c();
extern undefined4 FUN_80071f90();
extern undefined4 FUN_8007f6e4();
extern undefined4 FUN_8007f718();
extern int FUN_8007f764();
extern undefined4 FUN_8007f7b4();
extern undefined4 FUN_800810f0();
extern undefined4 FUN_800810f4();
extern undefined4 FUN_800810f8();
extern undefined4 FUN_80081108();
extern undefined4 FUN_80081114();
extern undefined4 FUN_80081118();
extern undefined8 FUN_800e842c();
extern undefined4 FUN_800e8630();
extern undefined4 FUN_8015061c();
extern undefined4 FUN_8020a3f8();
extern int FUN_8020a8c8();
extern undefined4 FUN_80247618();
extern undefined4 FUN_8024782c();
extern undefined4 FUN_80247a48();
extern undefined4 FUN_80247a7c();
extern undefined4 FUN_802570dc();
extern undefined4 FUN_80257b5c();
extern undefined4 FUN_80259000();
extern undefined4 FUN_80259288();
extern undefined4 FUN_8025c754();
extern undefined4 FUN_8025cce8();
extern undefined4 FUN_8025d180();
extern undefined4 FUN_8025d80c();
extern undefined4 FUN_8025d888();
extern undefined4 FUN_8025d8c4();
extern undefined4 FUN_80286814();
extern int FUN_8028682c();
extern int FUN_80286830();
extern int FUN_80286838();
extern int FUN_80286840();
extern undefined4 FUN_80286860();
extern undefined4 FUN_80286878();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286884();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_802924c4();
extern double FUN_80293900();
extern undefined4 FUN_8029397c();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern undefined4 FUN_80294c48();
extern undefined4 FUN_80294c60();
extern int FUN_80294cf8();
extern int FUN_80294d10();
extern undefined4 FUN_80294d60();
extern undefined4 FUN_80294d6c();

extern undefined4 DAT_802c29a0;
extern undefined4 DAT_802c29a4;
extern undefined4 DAT_802c29a8;
extern undefined4 DAT_802c29ac;
extern undefined4 DAT_802c29b0;
extern undefined4 DAT_802c29b4;
extern undefined4 DAT_802c29b8;
extern undefined4 DAT_802c29bc;
extern undefined4 DAT_802c29c0;
extern undefined4 DAT_802c29c4;
extern undefined4 DAT_802c29c8;
extern undefined4 DAT_802c29cc;
extern undefined4 DAT_802c29d0;
extern undefined4 DAT_802c29d4;
extern undefined4 DAT_802c29d8;
extern undefined4 DAT_802c29dc;
extern undefined4 DAT_802c29e0;
extern undefined4 DAT_802c29e4;
extern undefined4 DAT_802c29e8;
extern undefined4 DAT_802c29ec;
extern undefined4 DAT_803213b8;
extern undefined4 DAT_803213bc;
extern undefined4 DAT_803213c0;
extern undefined4 DAT_803213c4;
extern undefined4 DAT_803213c8;
extern undefined4 DAT_803213c9;
extern short DAT_803214f0;
extern undefined4 DAT_80321538;
extern undefined4 DAT_803215c8;
extern undefined4 DAT_803215c9;
extern undefined4 DAT_803215ca;
extern undefined4 DAT_80321618;
extern undefined4 DAT_80321678;
extern int DAT_80321688;
extern undefined4 DAT_80321698;
extern int DAT_803216a8;
extern undefined4 DAT_803ad318;
extern undefined4 DAT_803ad31c;
extern undefined4 DAT_803ad320;
extern undefined4 DAT_803ad324;
extern undefined4 DAT_803ad328;
extern undefined4 DAT_803ad32c;
extern undefined4 DAT_803ad330;
extern undefined4 DAT_803ad334;
extern undefined4 DAT_803ad338;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc9b8;
extern undefined4 DAT_803dc9c0;
extern undefined4 DAT_803dc9cc;
extern undefined4 DAT_803dc9d8;
extern undefined4 DAT_803dc9e0;
extern undefined4 DAT_803dc9e8;
extern undefined4 DAT_803dc9f0;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd6f4;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd6fc;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd718;
extern undefined4* DAT_803dd72c;
extern undefined4* DAT_803de720;
extern undefined4* DAT_803de724;
extern undefined4 DAT_803de728;
extern undefined4* DAT_803de730;
extern undefined4* DAT_803de734;
extern undefined4 DAT_803e3e38;
extern undefined4 DAT_cc008000;
extern f64 DOUBLE_803e3e28;
extern f64 DOUBLE_803e3e50;
extern f64 DOUBLE_803e3e88;
extern f64 DOUBLE_803e3eb0;
extern f64 DOUBLE_803e3ed0;
extern f64 DOUBLE_803e3f18;
extern f64 DOUBLE_803e3fb0;
extern f64 DOUBLE_803e4030;
extern f64 DOUBLE_803e4068;
extern f64 DOUBLE_803e4078;
extern f64 DOUBLE_803e40d0;
extern f32 lbl_803DC074;
extern f32 lbl_803DC9C8;
extern f32 lbl_803DC9D0;
extern f32 lbl_803DC9D4;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 lbl_803E3E30;
extern f32 lbl_803E3E34;
extern f32 lbl_803E3E3C;
extern f32 lbl_803E3E40;
extern f32 lbl_803E3E44;
extern f32 lbl_803E3E48;
extern f32 lbl_803E3E5C;
extern f32 lbl_803E3E60;
extern f32 lbl_803E3E64;
extern f32 lbl_803E3E68;
extern f32 lbl_803E3E6C;
extern f32 lbl_803E3E70;
extern f32 lbl_803E3E74;
extern f32 lbl_803E3E78;
extern f32 lbl_803E3E7C;
extern f32 lbl_803E3E94;
extern f32 lbl_803E3E98;
extern f32 lbl_803E3E9C;
extern f32 lbl_803E3EA0;
extern f32 lbl_803E3EA4;
extern f32 lbl_803E3EA8;
extern f32 lbl_803E3EBC;
extern f32 lbl_803E3EC0;
extern f32 lbl_803E3EC4;
extern f32 lbl_803E3EC8;
extern f32 lbl_803E3ED8;
extern f32 lbl_803E3EDC;
extern f32 lbl_803E3EE0;
extern f32 lbl_803E3EE4;
extern f32 lbl_803E3EE8;
extern f32 lbl_803E3EEC;
extern f32 lbl_803E3EF0;
extern f32 lbl_803E3EF4;
extern f32 lbl_803E3EF8;
extern f32 lbl_803E3EFC;
extern f32 lbl_803E3F00;
extern f32 lbl_803E3F04;
extern f32 lbl_803E3F08;
extern f32 lbl_803E3F0C;
extern f32 lbl_803E3F10;
extern f32 lbl_803E3F14;
extern f32 lbl_803E3F20;
extern f32 lbl_803E3F24;
extern f32 lbl_803E3F28;
extern f32 lbl_803E3F2C;
extern f32 lbl_803E3F30;
extern f32 lbl_803E3F34;
extern f32 lbl_803E3F38;
extern f32 lbl_803E3F3C;
extern f32 lbl_803E3F40;
extern f32 lbl_803E3F44;
extern f32 lbl_803E3F48;
extern f32 lbl_803E3F4C;
extern f32 lbl_803E3F50;
extern f32 lbl_803E3F54;
extern f32 lbl_803E3F58;
extern f32 lbl_803E3F5C;
extern f32 lbl_803E3F60;
extern f32 lbl_803E3F64;
extern f32 lbl_803E3F68;
extern f32 lbl_803E3F6C;
extern f32 lbl_803E3F70;
extern f32 lbl_803E3F74;
extern f32 lbl_803E3F78;
extern f32 lbl_803E3F7C;
extern f32 lbl_803E3F80;
extern f32 lbl_803E3F84;
extern f32 lbl_803E3F88;
extern f32 lbl_803E3F8C;
extern f32 lbl_803E3F90;
extern f32 lbl_803E3F94;
extern f32 lbl_803E3F98;
extern f32 lbl_803E3FA4;
extern f32 lbl_803E3FA8;
extern f32 lbl_803E3FB8;
extern f32 lbl_803E3FBC;
extern f32 lbl_803E3FC0;
extern f32 lbl_803E3FC4;
extern f32 lbl_803E3FC8;
extern f32 lbl_803E3FCC;
extern f32 lbl_803E3FD8;
extern f32 lbl_803E3FE8;
extern f32 lbl_803E3FF0;
extern f32 lbl_803E3FF4;
extern f32 lbl_803E3FF8;
extern f32 lbl_803E3FFC;
extern f32 lbl_803E4000;
extern f32 lbl_803E4004;
extern f32 lbl_803E4010;
extern f32 lbl_803E4014;
extern f32 lbl_803E4018;
extern f32 lbl_803E4024;
extern f32 lbl_803E4028;
extern f32 lbl_803E402C;
extern f32 lbl_803E4038;
extern f32 lbl_803E4040;
extern f32 lbl_803E4044;
extern f32 lbl_803E4048;
extern f32 lbl_803E404C;
extern f32 lbl_803E4050;
extern f32 lbl_803E4054;
extern f32 lbl_803E4058;
extern f32 lbl_803E405C;
extern f32 lbl_803E4060;
extern f32 lbl_803E4064;
extern f32 lbl_803E4070;
extern f32 lbl_803E4074;
extern f32 lbl_803E4080;
extern f32 lbl_803E4084;
extern f32 lbl_803E4098;
extern f32 lbl_803E409C;
extern f32 lbl_803E40A0;
extern f32 lbl_803E40A4;
extern f32 lbl_803E40A8;
extern f32 lbl_803E40AC;
extern f32 lbl_803E40B0;
extern f32 lbl_803E40B8;
extern f32 lbl_803E40BC;
extern f32 lbl_803E40C0;
extern f32 lbl_803E40C4;
extern f32 lbl_803E40C8;
extern f32 lbl_803E40E8;
extern f32 lbl_803E40EC;
extern void* PTR_DAT_803211ec;

/*
 * --INFO--
 *
 * Function: FUN_8016b2e0
 * EN v1.0 Address: 0x8016B2E0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8016B550
 * EN v1.1 Size: 412b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016b2e0(uint param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8016b2e4
 * EN v1.0 Address: 0x8016B2E4
 * EN v1.0 Size: 184b
 * EN v1.1 Address: 0x8016B6EC
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016b2e4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  int iVar1;
  int *piVar2;
  
  piVar2 = *(int **)(param_9 + 0xb8);
  iVar1 = *piVar2;
  if ((iVar1 != 0) && (param_10 == 0)) {
    FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1);
    *piVar2 = 0;
  }
  (**(code **)(*DAT_803dd6fc + 0x18))(param_9);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016b39c
 * EN v1.0 Address: 0x8016B39C
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8016B758
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016b39c(int param_1)
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
 * Function: FUN_8016b3c4
 * EN v1.0 Address: 0x8016B3C4
 * EN v1.0 Size: 1040b
 * EN v1.1 Address: 0x8016B78C
 * EN v1.1 Size: 780b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016b3c4(uint param_1)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  undefined8 uVar5;
  double dVar6;
  double dVar7;
  double in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined4 local_28;
  undefined4 local_24;
  undefined8 local_20;
  undefined8 local_18;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  uVar2 = (uint)*(byte *)(param_1 + 0x36);
  if (uVar2 < 0xff) {
    local_20 = (double)CONCAT44(0x43300000,uVar2);
    dVar6 = (double)(float)(local_20 - DOUBLE_803e3e50);
    in_f4 = (double)(lbl_803E3E5C * lbl_803DC074);
    if ((float)(dVar6 - in_f4) <= lbl_803E3E60) {
      dVar7 = DOUBLE_803e3e50;
      uVar5 = FUN_8000680c(param_1,0x7f);
      *(undefined *)(param_1 + 0x36) = 0;
      FUN_80017ac8(uVar5,dVar6,dVar7,in_f4,in_f5,in_f6,in_f7,in_f8,param_1);
      return;
    }
    local_20 = (double)CONCAT44(0x43300000,uVar2);
    iVar1 = (int)((double)(float)(local_20 - DOUBLE_803e3e50) - in_f4);
    local_18 = (double)(longlong)iVar1;
    *(char *)(param_1 + 0x36) = (char)iVar1;
  }
  else {
    *(float *)(param_1 + 0x28) = -(lbl_803E3E64 * lbl_803DC074 - *(float *)(param_1 + 0x28));
    if (*(float *)(param_1 + 0x28) < lbl_803E3E68) {
      *(float *)(param_1 + 0x28) = lbl_803E3E68;
    }
    FUN_80017a88((double)(*(float *)(param_1 + 0x24) * lbl_803DC074),
                 (double)(*(float *)(param_1 + 0x28) * lbl_803DC074),
                 (double)(*(float *)(param_1 + 0x2c) * lbl_803DC074),param_1);
  }
  if ((*(char *)(param_1 + 0x36) == -1) || (*(char *)(iVar3 + 0xc) != '\0')) {
    ObjHits_SetHitVolumeSlot(param_1,5,1,0);
    ObjHits_EnableObject(param_1);
    if ((*(int *)(*(int *)(param_1 + 0x54) + 0x50) == 0) ||
       (iVar1 = FUN_80017a98(), *(int *)(*(int *)(param_1 + 0x54) + 0x50) != iVar1)) {
      if ((*(float *)(param_1 + 0x10) <= *(float *)(iVar3 + 4)) && (*(char *)(param_1 + 0x36) == -1)
         ) {
        piVar4 = *(int **)(param_1 + 0xb8);
        local_28 = DAT_803e3e38;
        FUN_80006824(param_1,0x4a);
        uVar2 = FUN_80017760(0,2);
        (**(code **)(*(int *)piVar4[2] + 4))(param_1,uVar2,0,2,0xffffffff,&local_28);
        local_18 = (double)CONCAT44(0x43300000,(uint)*(byte *)(*(int *)(param_1 + 0x50) + 0x62));
        iVar1 = (int)(lbl_803E3E3C * (float)(local_18 - DOUBLE_803e3e50));
        local_20 = (double)(longlong)iVar1;
        FUN_80035b84(param_1,(short)iVar1);
        dVar6 = (double)lbl_803E3E44;
        dVar7 = (double)lbl_803E3E48;
        uVar5 = FUN_8000691c((double)lbl_803E3E40,dVar6,dVar7);
        *(undefined *)(param_1 + 0x36) = 0xfe;
        FUN_80017ac8(uVar5,dVar6,dVar7,in_f4,in_f5,in_f6,in_f7,in_f8,*piVar4);
        *piVar4 = 0;
        *(undefined *)(iVar3 + 0xc) = 1;
      }
    }
    else {
      if (*(char *)(param_1 + 0x36) == -1) {
        piVar4 = *(int **)(param_1 + 0xb8);
        local_24 = DAT_803e3e38;
        FUN_80006824(param_1,0x4a);
        uVar2 = FUN_80017760(0,2);
        (**(code **)(*(int *)piVar4[2] + 4))(param_1,uVar2,0,2,0xffffffff,&local_24);
        local_18 = (double)CONCAT44(0x43300000,(uint)*(byte *)(*(int *)(param_1 + 0x50) + 0x62));
        iVar3 = (int)(lbl_803E3E3C * (float)(local_18 - DOUBLE_803e3e50));
        local_20 = (double)(longlong)iVar3;
        FUN_80035b84(param_1,(short)iVar3);
        dVar6 = (double)lbl_803E3E44;
        dVar7 = (double)lbl_803E3E48;
        uVar5 = FUN_8000691c((double)lbl_803E3E40,dVar6,dVar7);
        *(undefined *)(param_1 + 0x36) = 0xfe;
        FUN_80017ac8(uVar5,dVar6,dVar7,in_f4,in_f5,in_f6,in_f7,in_f8,*piVar4);
        *piVar4 = 0;
      }
      ObjHits_DisableObject(param_1);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016b7d4
 * EN v1.0 Address: 0x8016B7D4
 * EN v1.0 Size: 412b
 * EN v1.1 Address: 0x8016BA98
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016b7d4(undefined2 *param_1)
{
  float fVar1;
  uint uVar2;
  undefined2 *puVar3;
  int iVar4;
  int *piVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  float local_18 [4];
  
  piVar5 = *(int **)(param_1 + 0x5c);
  ObjHits_DisableObject((int)param_1);
  *(undefined *)(param_1 + 0x1b) = 0xff;
  fVar1 = lbl_803E3E60;
  *(float *)(param_1 + 0x12) = lbl_803E3E60;
  *(float *)(param_1 + 0x14) = lbl_803E3E6C;
  *(float *)(param_1 + 0x16) = fVar1;
  param_1[1] = 0xc000;
  *param_1 = 0;
  param_1[2] = 0;
  dVar7 = (double)*(float *)(param_1 + 8);
  dVar8 = (double)*(float *)(param_1 + 10);
  FUN_800632d8((double)*(float *)(param_1 + 6),dVar7,dVar8,param_1,local_18,0);
  dVar6 = (double)*(float *)(param_1 + 8);
  piVar5[1] = (int)(float)(dVar6 - (double)local_18[0]);
  uVar2 = FUN_80017ae8();
  if ((uVar2 & 0xff) == 0) {
    *piVar5 = 0;
  }
  else {
    puVar3 = FUN_80017aa4(0x20,0xc);
    *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(param_1 + 10);
    *(undefined *)(puVar3 + 2) = 1;
    *(undefined *)((int)puVar3 + 5) = 1;
    *(undefined *)(puVar3 + 3) = 0xff;
    *(undefined *)((int)puVar3 + 7) = 0xff;
    iVar4 = FUN_80017a5c(dVar6,dVar7,dVar8,in_f4,in_f5,in_f6,in_f7,in_f8,(int)param_1,puVar3);
    *piVar5 = iVar4;
    *(undefined2 **)(*piVar5 + 0xc4) = param_1;
  }
  iVar4 = FUN_80006b14(0x5b);
  piVar5[2] = iVar4;
  *(undefined *)(piVar5 + 3) = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016b970
 * EN v1.0 Address: 0x8016B970
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x8016BBD0
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016b970(int param_1)
{
  char in_r8;
  
  if ((in_r8 != '\0') && (*(int *)(*(int *)(param_1 + 100) + 0xc) != 0)) {
    FUN_80061194();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016b9a8
 * EN v1.0 Address: 0x8016B9A8
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x8016BC1C
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016b9a8(int param_1)
{
  float fVar1;
  float fVar2;
  
  fVar2 = lbl_803E3E70;
  fVar1 = lbl_803E3E70 -
          (*(float *)(*(int *)(param_1 + 0xc4) + 0x10) - *(float *)(param_1 + 0x10)) /
          **(float **)(param_1 + 0xb8);
  **(float **)(param_1 + 100) = lbl_803E3E74 * fVar1 + lbl_803E3E70;
  fVar1 = fVar1 * lbl_803E3E78;
  if (fVar2 < fVar1) {
    fVar1 = fVar2;
  }
  *(short *)(*(int *)(param_1 + 100) + 0x36) = (short)(int)(lbl_803E3E7C * fVar1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016ba18
 * EN v1.0 Address: 0x8016BA18
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x8016BC8C
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016ba18(undefined2 *param_1)
{
  float *pfVar1;
  float local_18 [4];
  
  pfVar1 = *(float **)(param_1 + 0x5c);
  FUN_800632d8((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
               (double)*(float *)(param_1 + 10),param_1,local_18,0);
  ObjHits_DisableObject((int)param_1);
  *(undefined *)(param_1 + 0x1b) = 0xff;
  param_1[1] = 0x4000;
  *param_1 = 0;
  param_1[2] = 0;
  *(uint *)(*(int *)(param_1 + 0x32) + 0x30) = *(uint *)(*(int *)(param_1 + 0x32) + 0x30) | 0x10000;
  *pfVar1 = local_18[0];
  *(float *)(param_1 + 8) = *(float *)(param_1 + 8) - local_18[0];
  *(undefined2 *)(*(int *)(param_1 + 0x32) + 0x36) = 0;
  **(float **)(param_1 + 0x32) = lbl_803E3E70;
  return;
}

/*
 * --INFO--
 *
 * Function: staticCamera_free
 * EN v1.0 Address: 0x8016BAC4
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8016BD54
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void staticCamera_free(int param_1)
{
  ObjGroup_RemoveObject(param_1,7);
  return;
}

/*
 * --INFO--
 *
 * Function: staticCamera_render
 * EN v1.0 Address: 0x8016BAE8
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8016BD78
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void staticCamera_render(int param_1)
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
 * Function: staticCamera_init
 * EN v1.0 Address: 0x8016BB10
 * EN v1.0 Size: 168b
 * EN v1.1 Address: 0x8016BDB0
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void staticCamera_init(short *param_1,int param_2,int param_3)
{
  undefined *puVar1;
  
  *param_1 = -*(short *)(param_2 + 0x1c);
  param_1[1] = -*(short *)(param_2 + 0x1e);
  param_1[2] = -*(short *)(param_2 + 0x20);
  puVar1 = *(undefined **)(param_1 + 0x5c);
  *puVar1 = *(undefined *)(param_2 + 0x19);
  *(float *)(puVar1 + 4) =
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x1a)) - DOUBLE_803e3e88);
  puVar1[1] = 0;
  if (param_3 == 0) {
    ObjGroup_AddObject((int)param_1,7);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016bbb8
 * EN v1.0 Address: 0x8016BBB8
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x8016BE5C
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016bbb8(int param_1)
{
  char in_r8;
  
  if ((in_r8 != '\0') && (*(int *)(param_1 + 0xf4) == 0)) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016bbec
 * EN v1.0 Address: 0x8016BBEC
 * EN v1.0 Size: 324b
 * EN v1.1 Address: 0x8016BEA0
 * EN v1.1 Size: 224b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016bbec(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
  float *pfVar1;
  
  pfVar1 = *(float **)(param_9 + 0x5c);
  *pfVar1 = *pfVar1 - lbl_803DC074;
  if ((double)lbl_803E3E94 < (double)*pfVar1) {
    *param_9 = *param_9 + (short)(int)(lbl_803E3E98 * lbl_803DC074);
    param_9[2] = param_9[2] + (short)(int)(lbl_803E3E9C * lbl_803DC074);
    if (lbl_803E3EA0 < *pfVar1) {
      *(undefined *)(param_9 + 0x1b) = 0xff;
    }
    else {
      *(char *)(param_9 + 0x1b) = (char)(int)(lbl_803E3EA4 * *pfVar1 * lbl_803E3EA8);
    }
  }
  else {
    FUN_80017ac8((double)*pfVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 (int)param_9);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016bd30
 * EN v1.0 Address: 0x8016BD30
 * EN v1.0 Size: 80b
 * EN v1.1 Address: 0x8016BF80
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016bd30(int param_1,int param_2)
{
  **(float **)(param_1 + 0xb8) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000) -
              DOUBLE_803e3eb0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016bd80
 * EN v1.0 Address: 0x8016BD80
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8016BFD0
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016bd80(int param_1)
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
 * Function: FUN_8016bda8
 * EN v1.0 Address: 0x8016BDA8
 * EN v1.0 Size: 760b
 * EN v1.1 Address: 0x8016C004
 * EN v1.1 Size: 800b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016bda8(void)
{
  byte bVar1;
  short sVar2;
  uint uVar3;
  byte bVar4;
  int iVar5;
  uint uVar6;
  undefined4 *puVar7;
  int iVar8;
  char unaff_r27;
  int iVar9;
  int iVar10;
  double dVar11;
  undefined auStack_28 [4];
  uint local_24 [9];
  
  iVar5 = FUN_80286838();
  iVar10 = *(int *)(iVar5 + 0x4c);
  if (((((int)*(short *)(iVar10 + 0x20) == 0xffffffff) ||
       (uVar6 = FUN_80017690((int)*(short *)(iVar10 + 0x20)), uVar6 != 0)) &&
      (((int)*(short *)(iVar10 + 0x1e) == 0xffffffff ||
       (uVar6 = FUN_80017690((int)*(short *)(iVar10 + 0x1e)), uVar6 == 0)))) &&
     (puVar7 = ObjGroup_GetObjects(3,(int *)local_24), 0 < (int)local_24[0])) {
    iVar9 = CONCAT22(*(undefined2 *)(iVar10 + 0x1c),*(undefined2 *)(iVar10 + 0x1a));
    for (uVar6 = 0; (int)(uVar6 & 0xffff) < (int)local_24[0]; uVar6 = uVar6 + 1) {
      uVar3 = uVar6 & 0xffff;
      iVar8 = *(int *)(puVar7[uVar3] + 0x4c);
      if (iVar8 == 0) {
        unaff_r27 = '\x01';
      }
      else {
        unaff_r27 = '\0';
        if ((iVar9 == *(int *)(iVar8 + 0x14)) || (iVar9 == 0)) {
          unaff_r27 = '\x01';
        }
      }
      if (unaff_r27 != '\0') {
        unaff_r27 = '\0';
        dVar11 = FUN_80017714((float *)(iVar5 + 0x18),(float *)(puVar7[uVar3] + 0x18));
        if (dVar11 < (double)lbl_803E3EBC) {
          if (*(int *)(iVar5 + 0xf4) == 0) {
            uVar6 = FUN_80017760(1,100);
            if ((int)uVar6 <= (int)*(char *)(iVar10 + 0x19)) {
              bVar1 = *(byte *)(iVar10 + 0x18);
              bVar4 = (char)(bVar1 & 0x30) >> 4;
              if (bVar4 == 1) {
                iVar8 = (**(code **)(*DAT_803dd6d8 + 0x24))(auStack_28);
                if (iVar8 == 0) {
                  bVar1 = *(byte *)(iVar10 + 0x18);
                  iVar8 = puVar7[uVar3];
                  if ((int)*(short *)(iVar10 + 0x1e) != 0xffffffff) {
                    FUN_80017698((int)*(short *)(iVar10 + 0x1e),1);
                  }
                  sVar2 = *(short *)(iVar8 + 0x46);
                  if (sVar2 < 0x5b7) {
                    if ((sVar2 == 0x13a) || ((sVar2 < 0x13a && (sVar2 == 0x11)))) {
LAB_8016c228:
                      FUN_8015061c(iVar8,bVar1 & 0xf);
                    }
                  }
                  else if ((sVar2 == 0x5e1) || ((sVar2 < 0x5e1 && (sVar2 < 0x5ba))))
                  goto LAB_8016c228;
                }
              }
              else if (bVar4 == 0) {
                iVar8 = puVar7[uVar3];
                if ((int)*(short *)(iVar10 + 0x1e) != 0xffffffff) {
                  FUN_80017698((int)*(short *)(iVar10 + 0x1e),1);
                }
                sVar2 = *(short *)(iVar8 + 0x46);
                if (sVar2 < 0x5b7) {
                  if ((sVar2 == 0x13a) || ((sVar2 < 0x13a && (sVar2 == 0x11)))) {
LAB_8016c1a0:
                    FUN_8015061c(iVar8,bVar1 & 0xf);
                  }
                }
                else if ((sVar2 == 0x5e1) || ((sVar2 < 0x5e1 && (sVar2 < 0x5ba))))
                goto LAB_8016c1a0;
              }
              else if ((bVar4 < 3) &&
                      (iVar8 = (**(code **)(*DAT_803dd6d8 + 0x24))(auStack_28), iVar8 != 0)) {
                bVar1 = *(byte *)(iVar10 + 0x18);
                iVar8 = puVar7[uVar3];
                if ((int)*(short *)(iVar10 + 0x1e) != 0xffffffff) {
                  FUN_80017698((int)*(short *)(iVar10 + 0x1e),1);
                }
                sVar2 = *(short *)(iVar8 + 0x46);
                if (sVar2 < 0x5b7) {
                  if ((sVar2 == 0x13a) || ((sVar2 < 0x13a && (sVar2 == 0x11)))) {
LAB_8016c2b0:
                    FUN_8015061c(iVar8,bVar1 & 0xf);
                  }
                }
                else if ((sVar2 == 0x5e1) || ((sVar2 < 0x5e1 && (sVar2 < 0x5ba))))
                goto LAB_8016c2b0;
              }
            }
            *(undefined4 *)(iVar5 + 0xf4) = 1;
          }
          unaff_r27 = '\x01';
        }
        uVar6 = local_24[0] & 0xffff;
      }
    }
    if (unaff_r27 == '\0') {
      *(undefined4 *)(iVar5 + 0xf4) = 0;
    }
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016c0a0
 * EN v1.0 Address: 0x8016C0A0
 * EN v1.0 Size: 320b
 * EN v1.1 Address: 0x8016C324
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016c0a0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  undefined8 uVar1;
  
  (**(code **)(*DAT_803dd6d4 + 0x24))(*(undefined4 *)(param_9 + 0xb8));
  (**(code **)(*DAT_803dd6f4 + 8))(param_9,0xffff,0,0,0);
  FUN_800068c8(param_9);
  uVar1 = FUN_8000680c(param_9,0x7f);
  if ((*(short *)(param_9 + 0x46) == 0x774) && (*(char *)(param_9 + 0xeb) != '\0')) {
    FUN_80017ac8(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(int *)(param_9 + 200));
    ObjLink_DetachChild(param_9,*(int *)(param_9 + 200));
  }
  if (param_10 != 0) {
    FUN_8007f7b4();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016c1e0
 * EN v1.0 Address: 0x8016C1E0
 * EN v1.0 Size: 424b
 * EN v1.1 Address: 0x8016C3E8
 * EN v1.1 Size: 424b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016c1e0(ushort *param_1)
{
  ushort *puVar1;
  int iVar2;
  float afStack_278 [12];
  float afStack_248 [12];
  float afStack_218 [12];
  float afStack_1e8 [12];
  float afStack_1b8 [12];
  float afStack_188 [3];
  float local_17c;
  float local_16c;
  float local_15c;
  float afStack_158 [12];
  float afStack_128 [12];
  float afStack_f8 [12];
  float afStack_c8 [12];
  float afStack_98 [12];
  float afStack_68 [12];
  float afStack_38 [12];
  
  if ((*(byte *)(*(int *)(param_1 + 0x5c) + 0x7f) & 4) == 0) {
    FUN_8003b818((int)param_1);
  }
  else {
    FUN_80017a50(param_1,afStack_38,'\0');
    iVar2 = *(int *)(param_1 + 0x26);
    FUN_80247a48(-(double)(*(float *)(iVar2 + 8) - lbl_803DDA58),-(double)*(float *)(iVar2 + 0xc),
                 -(double)(*(float *)(iVar2 + 0x10) - lbl_803DDA5C),afStack_68);
    FUN_80247618(afStack_68,afStack_38,afStack_98);
    puVar1 = (ushort *)(**(code **)(*DAT_803dd6d0 + 0xc))();
    puVar1[1] = puVar1[1] + 0x8000;
    *(float *)(puVar1 + 4) = lbl_803E3EC0;
    FUN_80017a50(puVar1,afStack_188,'\0');
    puVar1[1] = puVar1[1] + 0x8000;
    *(float *)(puVar1 + 4) = lbl_803E3EC4;
    FUN_80247a48(-(double)local_17c,-(double)local_16c,-(double)local_15c,afStack_c8);
    FUN_8024782c((double)lbl_803E3EC8,afStack_f8,0x79);
    FUN_8024782c((double)lbl_803E3EC8,afStack_128,0x7a);
    FUN_80247a48((double)local_17c,(double)local_16c,(double)local_15c,afStack_158);
    FUN_80247618(afStack_c8,afStack_188,afStack_1b8);
    FUN_80247618(afStack_f8,afStack_1b8,afStack_1e8);
    FUN_80247618(afStack_128,afStack_1e8,afStack_218);
    FUN_80247618(afStack_158,afStack_218,afStack_248);
    FUN_80247618(afStack_248,afStack_98,afStack_278);
    FUN_8004036c(afStack_278);
    FUN_80040a88((int)param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016c388
 * EN v1.0 Address: 0x8016C388
 * EN v1.0 Size: 904b
 * EN v1.1 Address: 0x8016C590
 * EN v1.1 Size: 596b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016c388(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  byte bVar1;
  int *piVar2;
  uint uVar3;
  undefined2 *puVar4;
  int iVar5;
  undefined4 uVar6;
  int iVar7;
  undefined4 uVar8;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar9;
  int iVar10;
  int iVar11;
  undefined8 extraout_f1;
  undefined8 uVar12;
  int local_18;
  int local_14;
  
  iVar10 = *(int *)(param_9 + 0xb8);
  if ((*(int *)(param_9 + 0x4c) != 0) && (*(short *)(*(int *)(param_9 + 0x4c) + 0x18) != -1)) {
    local_14 = (**(code **)(*DAT_803dd6d4 + 0x14))((double)lbl_803DC074);
    uVar12 = extraout_f1;
    if ((local_14 != 0) && (*(short *)(param_9 + 0xb4) == -2)) {
      iVar9 = (int)*(char *)(iVar10 + 0x57);
      iVar11 = 0;
      piVar2 = (int *)FUN_80017b00(&local_14,&local_18);
      iVar7 = 0;
      for (local_14 = 0; local_14 < local_18; local_14 = local_14 + 1) {
        iVar5 = *piVar2;
        if (*(short *)(iVar5 + 0xb4) == iVar9) {
          iVar11 = iVar5;
        }
        if (((*(short *)(iVar5 + 0xb4) == -2) && (*(short *)(iVar5 + 0x44) == 0x10)) &&
           (iVar10 = *(int *)(iVar5 + 0xb8), iVar9 == *(char *)(iVar10 + 0x57))) {
          iVar7 = iVar7 + 1;
        }
        piVar2 = piVar2 + 1;
      }
      if (((iVar7 < 2) && (iVar11 != 0)) && (*(short *)(iVar11 + 0xb4) != -1)) {
        *(undefined2 *)(iVar11 + 0xb4) = 0xffff;
        uVar12 = (**(code **)(*DAT_803dd6d4 + 0x4c))(iVar9);
      }
      *(undefined2 *)(param_9 + 0xb4) = 0xffff;
      *(ushort *)(param_9 + 0xb0) = *(ushort *)(param_9 + 0xb0) | 0x8000;
      *(ushort *)(param_9 + 6) = *(ushort *)(param_9 + 6) | 0x4000;
    }
    if (*(short *)(param_9 + 0x46) == 0x774) {
      for (iVar11 = 0; iVar11 < (int)(uint)*(byte *)(iVar10 + 0x8b); iVar11 = iVar11 + 1) {
        bVar1 = *(byte *)(iVar10 + iVar11 + 0x81);
        if (bVar1 == 0xb) {
          if (*(char *)(param_9 + 0xeb) != '\0') {
            FUN_80017ac8(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         *(int *)(param_9 + 200));
            uVar12 = ObjLink_DetachChild(param_9,*(int *)(param_9 + 200));
          }
        }
        else if (((bVar1 < 0xb) && (9 < bVar1)) && (uVar3 = FUN_80017ae8(), (uVar3 & 0xff) != 0)) {
          puVar4 = FUN_80017aa4(0x18,0x69);
          uVar6 = 0xffffffff;
          uVar8 = 0;
          iVar7 = FUN_80017ae4(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar4
                               ,4,0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
          ObjLink_AttachChild(param_9,iVar7,0);
          FUN_800305f8((double)lbl_803E3EC4,param_2,param_3,param_4,param_5,param_6,param_7,
                       param_8,iVar7,0,0,uVar6,uVar8,in_r8,in_r9,in_r10);
          param_2 = (double)lbl_803DC074;
          uVar12 = FUN_8002fc3c((double)lbl_803E3EC0,param_2);
        }
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016c710
 * EN v1.0 Address: 0x8016C710
 * EN v1.0 Size: 404b
 * EN v1.1 Address: 0x8016C7E4
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016c710(int param_1,int param_2)
{
  int iVar1;
  int iVar2;
  
  FUN_80017a7c(param_1,'d');
  iVar2 = *(int *)(param_1 + 0xb8);
  *(undefined2 *)(iVar2 + 0x6a) = *(undefined2 *)(param_2 + 0x1a);
  *(undefined2 *)(iVar2 + 0x6e) = 0xffff;
  *(float *)(iVar2 + 0x24) =
       lbl_803E3EC0 /
       (lbl_803E3EC0 +
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x24)) - DOUBLE_803e3ed0));
  *(undefined4 *)(iVar2 + 0x28) = 0xffffffff;
  *(undefined4 *)(iVar2 + 0x98) = 0;
  *(undefined4 *)(iVar2 + 0x94) = 0;
  *(undefined2 *)(iVar2 + 0x116) = 0;
  *(undefined2 *)(iVar2 + 0x114) = 0;
  *(undefined4 *)(iVar2 + 0xe8) = 0;
  iVar1 = *(int *)(param_1 + 0xf4);
  if ((iVar1 == 0) && (*(short *)(param_2 + 0x18) != 1)) {
    (**(code **)(*DAT_803dd6d4 + 0x1c))(iVar2,param_2);
    *(int *)(param_1 + 0xf4) = *(short *)(param_2 + 0x18) + 1;
  }
  else if ((iVar1 != 0) && ((int)*(short *)(param_2 + 0x18) != iVar1 + -1)) {
    (**(code **)(*DAT_803dd6d4 + 0x24))(iVar2);
    if (*(short *)(param_2 + 0x18) != -1) {
      (**(code **)(*DAT_803dd6d4 + 0x1c))(iVar2,param_2);
    }
    *(int *)(param_1 + 0xf4) = *(short *)(param_2 + 0x18) + 1;
  }
  if (*(int *)(param_1 + 100) != 0) {
    *(undefined *)(*(int *)(param_1 + 100) + 0x3a) = 100;
    *(undefined *)(*(int *)(param_1 + 100) + 0x3b) = 0x96;
  }
  FUN_80017a0c(param_1,0xff);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016c8a4
 * EN v1.0 Address: 0x8016C8A4
 * EN v1.0 Size: 424b
 * EN v1.1 Address: 0x8016C958
 * EN v1.1 Size: 684b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016c8a4(int param_1)
{
  float fVar1;
  uint uVar2;
  int iVar3;
  byte bVar4;
  double dVar5;
  undefined auStack_38 [8];
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  
  if ((*(uint *)(param_1 + 0xf8) & 4) != 0) {
    dVar5 = (double)lbl_803E3ED8;
    for (bVar4 = 0; bVar4 < 10; bVar4 = bVar4 + 1) {
      fVar1 = *(float *)(param_1 + 8);
      uVar2 = (uint)bVar4;
      local_2c = (float)(dVar5 * (double)(fVar1 * (float)(&DAT_803213b8)[uVar2 * 5]));
      local_28 = (float)(dVar5 * (double)(fVar1 * (float)(&DAT_803213bc)[uVar2 * 5]));
      local_24 = (float)(dVar5 * (double)(fVar1 * (float)(&DAT_803213c0)[uVar2 * 5]));
      FUN_800810f0((double)(fVar1 * (float)(&DAT_803213c4)[uVar2 * 5]),param_1,3,
                   (uint)(byte)(&DAT_803213c8)[uVar2 * 0x14],
                   (uint)(byte)(&DAT_803213c9)[uVar2 * 0x14],(int)auStack_38);
    }
  }
  local_30 = lbl_803E3EDC;
  if ((*(uint *)(param_1 + 0xf8) & 1) != 0) {
    fVar1 = *(float *)(param_1 + 8);
    local_2c = lbl_803E3ED8 * lbl_803E3EE0 * fVar1;
    local_28 = lbl_803E3ED8 * lbl_803E3EE4 * fVar1;
    local_24 = lbl_803E3ED8 * lbl_803E3EE8 * fVar1;
    FUN_80081108((double)(lbl_803E3EEC * fVar1),(double)lbl_803E3EF0);
    local_2c = lbl_803E3EF4;
    fVar1 = *(float *)(param_1 + 8);
    local_28 = lbl_803E3ED8 * lbl_803E3EF8 * fVar1;
    local_24 = lbl_803E3ED8 * lbl_803E3EFC * fVar1;
    FUN_80081108((double)(lbl_803E3EEC * fVar1),(double)lbl_803E3F00);
    fVar1 = *(float *)(param_1 + 8);
    local_2c = lbl_803E3ED8 * lbl_803E3F04 * fVar1;
    local_28 = lbl_803E3ED8 * lbl_803E3EE4 * fVar1;
    local_24 = lbl_803E3ED8 * lbl_803E3EE8 * fVar1;
    FUN_80081108((double)(lbl_803E3EEC * fVar1),(double)lbl_803E3EF0);
  }
  if (*(short *)(param_1 + 0x46) == 0xa8) {
    FUN_800810f4((double)lbl_803E3F08,(double)lbl_803E3F0C,param_1,7,5,1,10,0,0x20000000);
  }
  else if (*(short *)(param_1 + 0x46) == 0x451) {
    iVar3 = FUN_80017a54(param_1);
    *(undefined *)(*(int *)(iVar3 + 0x34) + 8) = 2;
    if ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0) {
      FUN_800810f4((double)lbl_803E3F08,(double)lbl_803E3F10,param_1,5,2,1,0x14,0,0);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016ca4c
 * EN v1.0 Address: 0x8016CA4C
 * EN v1.0 Size: 128b
 * EN v1.1 Address: 0x8016CC04
 * EN v1.1 Size: 120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016ca4c(int param_1)
{
  (**(code **)(*DAT_803dd6d4 + 0x24))(*(undefined4 *)(param_1 + 0xb8));
  (**(code **)(*DAT_803dd6f4 + 8))(param_1,0xffff,0,0,0);
  FUN_8000680c(param_1,0x7f);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016cacc
 * EN v1.0 Address: 0x8016CACC
 * EN v1.0 Size: 444b
 * EN v1.1 Address: 0x8016CC7C
 * EN v1.1 Size: 468b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016cacc(void)
{
  ushort *puVar1;
  ushort *puVar2;
  int iVar3;
  float afStack_288 [12];
  float afStack_258 [12];
  float afStack_228 [12];
  float afStack_1f8 [12];
  float afStack_1c8 [12];
  float afStack_198 [3];
  float local_18c;
  float local_17c;
  float local_16c;
  float afStack_168 [12];
  float afStack_138 [12];
  float afStack_108 [12];
  float afStack_d8 [12];
  float afStack_a8 [12];
  float afStack_78 [12];
  float afStack_48 [18];
  
  puVar1 = (ushort *)FUN_80286840();
  FUN_8016c8a4((int)puVar1);
  if ((*(byte *)(*(int *)(puVar1 + 0x5c) + 0x7f) & 4) == 0) {
    FUN_8003b818((int)puVar1);
  }
  else {
    FUN_80017a50(puVar1,afStack_48,'\0');
    iVar3 = *(int *)(puVar1 + 0x26);
    FUN_80247a48(-(double)(*(float *)(iVar3 + 8) - lbl_803DDA58),-(double)*(float *)(iVar3 + 0xc),
                 -(double)(*(float *)(iVar3 + 0x10) - lbl_803DDA5C),afStack_78);
    FUN_80247618(afStack_78,afStack_48,afStack_a8);
    puVar2 = (ushort *)(**(code **)(*DAT_803dd6d0 + 0xc))();
    puVar2[1] = puVar2[1] + 0x8000;
    *(float *)(puVar2 + 4) = lbl_803E3F08;
    FUN_80017a50(puVar2,afStack_198,'\0');
    puVar2[1] = puVar2[1] + 0x8000;
    *(float *)(puVar2 + 4) = lbl_803E3EF4;
    FUN_80247a48(-(double)local_18c,-(double)local_17c,-(double)local_16c,afStack_d8);
    FUN_8024782c((double)lbl_803E3F14,afStack_108,0x79);
    FUN_8024782c((double)lbl_803E3F14,afStack_138,0x7a);
    FUN_80247a48((double)local_18c,(double)local_17c,(double)local_16c,afStack_168);
    FUN_80247618(afStack_d8,afStack_198,afStack_1c8);
    FUN_80247618(afStack_108,afStack_1c8,afStack_1f8);
    FUN_80247618(afStack_138,afStack_1f8,afStack_228);
    FUN_80247618(afStack_168,afStack_228,afStack_258);
    FUN_80247618(afStack_258,afStack_a8,afStack_288);
    FUN_8004036c(afStack_288);
    FUN_80040a88((int)puVar1);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016cc88
 * EN v1.0 Address: 0x8016CC88
 * EN v1.0 Size: 556b
 * EN v1.1 Address: 0x8016CE50
 * EN v1.1 Size: 572b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016cc88(int param_1)
{
  byte bVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int local_38;
  int local_34;
  undefined auStack_30 [12];
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  
  iVar6 = *(int *)(param_1 + 0xb8);
  if ((*(int *)(param_1 + 0x4c) != 0) && (*(short *)(*(int *)(param_1 + 0x4c) + 0x18) != -1)) {
    for (local_38 = 0; local_38 < (int)(uint)*(byte *)(iVar6 + 0x8b); local_38 = local_38 + 1) {
      bVar1 = *(byte *)(iVar6 + local_38 + 0x81);
      if (bVar1 == 3) {
        *(uint *)(param_1 + 0xf8) = *(uint *)(param_1 + 0xf8) ^ 4;
      }
      else if (bVar1 < 3) {
        if (bVar1 == 1) {
          *(uint *)(param_1 + 0xf8) = *(uint *)(param_1 + 0xf8) ^ 1;
        }
        else if (bVar1 != 0) {
          *(uint *)(param_1 + 0xf8) = *(uint *)(param_1 + 0xf8) ^ 2;
        }
      }
      else if (bVar1 < 5) {
        local_24 = *(undefined4 *)(param_1 + 0xc);
        local_20 = *(undefined4 *)(param_1 + 0x10);
        local_1c = *(undefined4 *)(param_1 + 0x14);
        iVar4 = 3;
        do {
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x7fe,auStack_30,0x200001,0xffffffff,0);
          iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
      }
    }
    local_38 = (**(code **)(*DAT_803dd6d4 + 0x14))((double)lbl_803DC074,param_1);
    if ((local_38 != 0) && (*(short *)(param_1 + 0xb4) == -2)) {
      iVar5 = (int)*(char *)(iVar6 + 0x57);
      iVar6 = 0;
      piVar2 = (int *)FUN_80017b00(&local_38,&local_34);
      iVar4 = 0;
      for (local_38 = 0; local_38 < local_34; local_38 = local_38 + 1) {
        iVar3 = *piVar2;
        if (*(short *)(iVar3 + 0xb4) == iVar5) {
          iVar6 = iVar3;
        }
        if (((*(short *)(iVar3 + 0xb4) == -2) && (*(short *)(iVar3 + 0x44) == 0x10)) &&
           (iVar5 == *(char *)(*(int *)(iVar3 + 0xb8) + 0x57))) {
          iVar4 = iVar4 + 1;
        }
        piVar2 = piVar2 + 1;
      }
      if (((iVar4 < 2) && (iVar6 != 0)) && (*(short *)(iVar6 + 0xb4) != -1)) {
        *(undefined2 *)(iVar6 + 0xb4) = 0xffff;
        (**(code **)(*DAT_803dd6d4 + 0x4c))(iVar5);
      }
      *(undefined2 *)(param_1 + 0xb4) = 0xffff;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016ceb4
 * EN v1.0 Address: 0x8016CEB4
 * EN v1.0 Size: 392b
 * EN v1.1 Address: 0x8016D08C
 * EN v1.1 Size: 360b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016ceb4(int param_1,int param_2)
{
  int iVar1;
  int iVar2;
  
  FUN_80017a7c(param_1,'d');
  iVar2 = *(int *)(param_1 + 0xb8);
  *(undefined2 *)(iVar2 + 0x6a) = *(undefined2 *)(param_2 + 0x1a);
  *(undefined2 *)(iVar2 + 0x6e) = 0xffff;
  *(float *)(iVar2 + 0x24) =
       lbl_803E3F08 /
       (lbl_803E3F08 +
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x24)) - DOUBLE_803e3f18));
  *(undefined4 *)(iVar2 + 0x28) = 0xffffffff;
  *(undefined4 *)(iVar2 + 0x98) = 0;
  *(undefined4 *)(iVar2 + 0x94) = 0;
  *(undefined2 *)(iVar2 + 0x116) = 0;
  *(undefined2 *)(iVar2 + 0x114) = 0;
  *(undefined4 *)(param_1 + 0xf8) = 0;
  iVar1 = *(int *)(param_1 + 0xf4);
  if ((iVar1 == 0) && (*(short *)(param_2 + 0x18) != 1)) {
    (**(code **)(*DAT_803dd6d4 + 0x1c))(iVar2,param_2);
    *(int *)(param_1 + 0xf4) = *(short *)(param_2 + 0x18) + 1;
  }
  else if ((iVar1 != 0) && ((int)*(short *)(param_2 + 0x18) != iVar1 + -1)) {
    (**(code **)(*DAT_803dd6d4 + 0x24))(iVar2);
    if (*(short *)(param_2 + 0x18) != -1) {
      (**(code **)(*DAT_803dd6d4 + 0x1c))(iVar2,param_2);
    }
    *(int *)(param_1 + 0xf4) = *(short *)(param_2 + 0x18) + 1;
  }
  if (*(int *)(param_1 + 100) != 0) {
    *(undefined *)(*(int *)(param_1 + 100) + 0x3a) = 100;
    *(undefined *)(*(int *)(param_1 + 100) + 0x3b) = 0x96;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016d03c
 * EN v1.0 Address: 0x8016D03C
 * EN v1.0 Size: 276b
 * EN v1.1 Address: 0x8016D1F4
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8016d03c(int param_1,undefined4 param_2,int param_3)
{
  byte bVar1;
  int iVar2;
  byte *pbVar3;
  
  pbVar3 = *(byte **)(param_1 + 0xb8);
  if ((char)*pbVar3 < '\0') {
    FUN_80053bb0((double)*(float *)(param_1 + 0x18),(double)*(float *)(param_1 + 0x1c),
                 (double)*(float *)(param_1 + 0x20),pbVar3[1],pbVar3[2]);
  }
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar2 = iVar2 + 1) {
    bVar1 = *(byte *)(param_3 + iVar2 + 0x81);
    if (bVar1 == 2) {
      *pbVar3 = *pbVar3 & 0x7f | 0x80;
      pbVar3[1] = 1;
      pbVar3[2] = 0;
    }
    else if (bVar1 < 2) {
      if (bVar1 == 0) {
        *pbVar3 = *pbVar3 & 0x7f;
        FUN_80053ba4();
      }
      else {
        *pbVar3 = *pbVar3 & 0x7f | 0x80;
        pbVar3[1] = 0;
      }
    }
    else if (bVar1 < 4) {
      *pbVar3 = *pbVar3 & 0x7f | 0x80;
      pbVar3[2] = 1;
      pbVar3[1] = 0;
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8016d150
 * EN v1.0 Address: 0x8016D150
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x8016D31C
 * EN v1.1 Size: 120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016d150(int param_1)
{
  byte bVar1;
  
  bVar1 = **(byte **)(param_1 + 0xb8);
  if ((char)bVar1 < '\0') {
    **(byte **)(param_1 + 0xb8) = bVar1 & 0x7f;
    FUN_80053ba4();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016d188
 * EN v1.0 Address: 0x8016D188
 * EN v1.0 Size: 2060b
 * EN v1.1 Address: 0x8016D394
 * EN v1.1 Size: 2820b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016d188(int param_1,int param_2)
{
  float fVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  double dVar5;
  int local_58;
  float local_54;
  int local_50;
  undefined2 local_4c [3];
  short local_46;
  float local_44;
  undefined2 local_34;
  undefined2 local_32;
  undefined2 local_30;
  short local_2e;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 local_20;
  longlong local_18;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  if ((param_1 != 0) && (param_2 != 0)) {
    if (*(char *)(iVar4 + 0xba) != '\0') {
      iVar2 = FUN_80294d10(param_2);
      if (iVar2 == 0) {
        local_54 = lbl_803E3F24;
        fVar1 = lbl_803E3F28;
      }
      else {
        local_54 = lbl_803E3F20;
        fVar1 = lbl_803E3F20;
      }
      if (*(byte *)(iVar4 + 0xbb) == 7) {
        dVar5 = (double)lbl_803E3F2C;
        local_18 = (longlong)(int)(lbl_803E3F30 * fVar1);
        FUN_800810f8(dVar5,dVar5,dVar5,(double)(lbl_803E3F34 * local_54),param_1,7,
                     (uint)*(byte *)(iVar4 + 0xba),1,(int)(lbl_803E3F30 * fVar1),0,0);
      }
      else {
        dVar5 = (double)lbl_803E3F20;
        local_18 = (longlong)(int)(lbl_803E3F30 * fVar1);
        FUN_800810f8(dVar5,dVar5,dVar5,(double)(lbl_803E3F34 * local_54),param_1,
                     (uint)*(byte *)(iVar4 + 0xbb),(uint)*(byte *)(iVar4 + 0xba),1,
                     (int)(lbl_803E3F30 * fVar1),0,0);
      }
    }
    FUN_80294c60(param_2,&local_50,&local_54);
    local_34 = 0;
    local_32 = 0;
    local_30 = 0;
    local_2c = lbl_803E3F20;
    if (local_50 == 0x87) {
      iVar4 = (int)(lbl_803E3F38 * (local_54 / lbl_803E3F30));
      local_18 = (longlong)iVar4;
      local_2e = 0x15 - (short)iVar4;
      local_28 = lbl_803E3F3C * (local_54 / lbl_803E3F40 - lbl_803E3F2C);
      local_34 = 0xc94;
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
      local_2e = 9;
      local_2c = lbl_803E3F48 * (local_54 / lbl_803E3F40) + lbl_803E3F44;
      local_24 = lbl_803E3F4C;
      local_34 = 0xc0e;
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b3,&local_34,2,0xffffffff,0);
    }
    else if (local_50 < 0x87) {
      if (local_50 == 0x7f) {
        local_2c = lbl_803E3F58;
        local_2e = 10;
        local_24 = lbl_803E3F54;
        local_28 = lbl_803E3F50;
        local_34 = 0xc0e;
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b3,&local_34,2,0xffffffff,0);
      }
      else if (local_50 < 0x7f) {
        if ((local_50 == 0x43) && (lbl_803E3F4C < local_54)) {
          iVar4 = (int)(lbl_803E3F38 * (local_54 / lbl_803E3F30));
          local_18 = (longlong)iVar4;
          local_2e = (short)iVar4 + 6;
          local_28 = lbl_803E3F3C * (local_54 / lbl_803E3F40 - lbl_803E3F2C);
          local_34 = 0xc94;
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b4,&local_34,2,0xffffffff,0);
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b4,&local_34,2,0xffffffff,0);
          local_2e = 9;
          local_2c = lbl_803E3F48 * (local_54 / lbl_803E3F40) + lbl_803E3F44;
          local_24 = lbl_803E3F4C;
          local_34 = 0xc0e;
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b3,&local_34,2,0xffffffff,0);
        }
      }
      else if (local_50 == 0x85) {
        if (lbl_803E3F4C < local_54) {
          uVar3 = FUN_80017690(0xc55);
          if (uVar3 == 0) {
            fVar1 = local_54 / lbl_803E3F40;
            iVar4 = (int)(lbl_803E3F38 * fVar1);
            local_2e = (short)iVar4;
            local_34 = 0xc94;
          }
          else {
            fVar1 = local_54 / lbl_803E3F50;
            iVar4 = (int)(lbl_803E3F38 * fVar1);
            local_2e = (short)iVar4;
            local_34 = 0xc75;
          }
          local_18 = (longlong)iVar4;
          local_28 = lbl_803E3F5C * (lbl_803E3F28 - fVar1);
          local_2e = 0x15 - local_2e;
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
          local_2e = 9;
          uVar3 = FUN_80017690(0xc55);
          if (uVar3 == 0) {
            local_34 = 0xc0e;
            fVar1 = lbl_803E3F40;
          }
          else {
            local_34 = 0xc75;
            fVar1 = lbl_803E3F50;
          }
          local_2c = lbl_803E3F48 * (local_54 / fVar1) + lbl_803E3F44;
          local_24 = lbl_803E3F4C;
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b3,&local_34,2,0xffffffff,0);
        }
      }
      else if (0x84 < local_50) {
        uVar3 = FUN_80017690(0xc55);
        if (uVar3 == 0) {
          local_34 = 0xc0e;
        }
        else {
          local_34 = 0xc75;
        }
        fVar1 = *(float *)(param_2 + 0x98);
        if (lbl_803E3F68 <= fVar1) {
          if (fVar1 < lbl_803E3F70) {
            local_28 = lbl_803E3F5C * (lbl_803E3F74 * (fVar1 - lbl_803E3F68) - lbl_803E3F2C)
            ;
            local_2e = 9;
            local_2c = lbl_803E3F20;
            local_24 = lbl_803E3F4C;
            (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b3,&local_34,2,0xffffffff,0);
          }
        }
        else {
          local_28 = lbl_803E3F6C;
          local_2e = 9;
          local_2c = lbl_803E3F20;
          local_24 = lbl_803E3F4C;
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b3,&local_34,2,0xffffffff,0);
        }
      }
    }
    else if (local_50 == 0x468) {
      if (lbl_803E3F4C < local_54) {
        iVar4 = (int)(lbl_803E3F38 * (local_54 / lbl_803E3F60));
        local_18 = (longlong)iVar4;
        local_46 = 0x15 - (short)iVar4;
        local_4c[0] = 0xc95;
        FUN_80294c48(*(int *)(param_1 + 0xc4),&local_58);
        local_28 = *(float *)(local_58 + 0xc);
        local_24 = *(float *)(local_58 + 0x10);
        local_20 = *(undefined4 *)(local_58 + 0x14);
        (**(code **)(*DAT_803dd708 + 8))
                  (*(undefined4 *)(param_1 + 0xc4),0x7b9,&local_34,0x200001,0xffffffff,local_4c);
        (**(code **)(*DAT_803dd708 + 8))
                  (*(undefined4 *)(param_1 + 0xc4),0x7b9,&local_34,0x200001,0xffffffff,local_4c);
        (**(code **)(*DAT_803dd708 + 8))
                  (*(undefined4 *)(param_1 + 0xc4),0x7b9,&local_34,0x200001,0xffffffff,local_4c);
        (**(code **)(*DAT_803dd708 + 8))
                  (*(undefined4 *)(param_1 + 0xc4),0x7b9,&local_34,0x200001,0xffffffff,local_4c);
        local_46 = 9;
        local_4c[0] = 0xc95;
        local_44 = lbl_803E3F64 * (local_54 / lbl_803E3F60) + lbl_803E3F44;
        local_28 = *(float *)(local_58 + 0xc);
        local_24 = *(float *)(local_58 + 0x10);
        local_20 = *(undefined4 *)(local_58 + 0x14);
        (**(code **)(*DAT_803dd708 + 8))
                  (*(undefined4 *)(param_1 + 0xc4),0x7ba,&local_34,0x200001,0xffffffff,local_4c);
      }
    }
    else if (local_50 < 0x468) {
      if (local_50 < 0x89) {
        local_2e = 0x23;
        local_24 = lbl_803E3F4C;
        local_28 = lbl_803E3F50;
        local_34 = 0xc0e;
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b3,&local_34,2,0xffffffff,0);
        local_2e = 0x12;
        local_24 = lbl_803E3F54;
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b3,&local_34,2,0xffffffff,0);
      }
    }
    else if ((local_50 == 0x46f) && (lbl_803E3F4C < local_54)) {
      iVar4 = (int)(lbl_803E3F38 * (local_54 / lbl_803E3F60));
      local_18 = (longlong)iVar4;
      local_2e = 0x15 - (short)iVar4;
      local_28 = lbl_803E3F5C * (lbl_803E3F28 - local_54 / lbl_803E3F60);
      local_34 = 0xc94;
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
      local_2e = 9;
      local_2c = lbl_803E3F48 * (local_54 / lbl_803E3F60) + lbl_803E3F44;
      local_24 = lbl_803E3F4C;
      local_34 = 0xc0e;
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b3,&local_34,2,0xffffffff,0);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016d994
 * EN v1.0 Address: 0x8016D994
 * EN v1.0 Size: 16b
 * EN v1.1 Address: 0x8016DE98
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016d994(int param_1,undefined param_2,undefined param_3)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(undefined *)(iVar1 + 0xbb) = param_2;
  *(undefined *)(iVar1 + 0xba) = param_3;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016d9a4
 * EN v1.0 Address: 0x8016D9A4
 * EN v1.0 Size: 692b
 * EN v1.1 Address: 0x8016DEA8
 * EN v1.1 Size: 504b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016d9a4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 *param_9)
{
  int iVar1;
  uint uVar2;
  undefined2 *puVar3;
  undefined4 uVar4;
  int iVar5;
  undefined4 in_r10;
  undefined8 uVar6;
  double dVar7;
  double dVar8;
  undefined2 local_28;
  undefined2 local_26;
  undefined2 local_24;
  float local_20;
  undefined4 local_1c;
  float local_18;
  undefined4 local_14;
  
  if (DAT_803ad338 != '\0') {
    FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803ad334);
    DAT_803ad334 = 0;
  }
  DAT_803ad318 = *param_9;
  dVar7 = (double)lbl_803E3F40;
  DAT_803ad31c = (float)(dVar7 + (double)(float)param_9[1]);
  DAT_803ad320 = param_9[2];
  DAT_803ad330 = lbl_803E3F8C;
  DAT_803ad324 = lbl_803E3F20;
  DAT_803ad328 = lbl_803E3F28;
  DAT_803ad32c = lbl_803E3F20;
  dVar8 = (double)lbl_803E3F94;
  FUN_8000691c((double)lbl_803E3F90,dVar7,dVar8);
  iVar1 = FUN_80017a98();
  if ((iVar1 != 0) && (uVar2 = FUN_80017ae8(), (uVar2 & 0xff) != 0)) {
    DAT_803ad338 = '\x01';
    local_1c = DAT_803ad318;
    local_18 = DAT_803ad31c;
    local_14 = DAT_803ad320;
    local_20 = lbl_803E3F20;
    local_28 = 0;
    local_24 = 0;
    local_26 = 0;
    uVar4 = 0;
    iVar5 = *DAT_803dd708;
    uVar6 = (**(code **)(iVar5 + 8))(iVar1,0x565,&local_28,0x200000,0xffffffff);
    puVar3 = FUN_80017aa4(0x24,0x63c);
    *(undefined *)(puVar3 + 2) = 1;
    *(undefined *)(puVar3 + 3) = 0xff;
    *(undefined *)((int)puVar3 + 5) = 2;
    *(undefined *)((int)puVar3 + 7) = 0xff;
    *(undefined4 *)(puVar3 + 4) = DAT_803ad318;
    *(float *)(puVar3 + 6) = DAT_803ad31c;
    *(undefined4 *)(puVar3 + 8) = DAT_803ad320;
    DAT_803ad334 = FUN_80017ae4(uVar6,dVar7,dVar8,param_4,param_5,param_6,param_7,param_8,puVar3,5,
                                *(undefined *)(iVar1 + 0xac),0xffffffff,*(uint **)(iVar1 + 0x30),
                                uVar4,iVar5,in_r10);
    uVar2 = FUN_80017690(0xc55);
    if (uVar2 != 0) {
      *(undefined *)(DAT_803ad334 + 0xad) = 1;
    }
    FUN_80035b84(DAT_803ad334,1);
    ObjHits_SetHitVolumeSlot(DAT_803ad334,0x11,5,0);
    *(float *)(DAT_803ad334 + 8) = lbl_803E3F68;
    *(undefined *)(DAT_803ad334 + 0x36) = 0xff;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016dc58
 * EN v1.0 Address: 0x8016DC58
 * EN v1.0 Size: 384b
 * EN v1.1 Address: 0x8016E0A0
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016dc58(void)
{
  undefined *puVar1;
  double dVar2;
  float afStack_f8 [12];
  float afStack_c8 [12];
  float afStack_98 [12];
  float afStack_68 [12];
  float afStack_38 [3];
  float local_2c;
  float local_1c;
  float local_c;
  longlong local_8;
  
  if (DAT_803ad338 != '\0') {
    local_8 = (longlong)(int)DAT_803ad330;
    FUN_8006fb18((char)(int)DAT_803ad330);
    puVar1 = FUN_80006974();
    FUN_80003494((uint)afStack_f8,(uint)puVar1,0x30);
    FUN_8024782c((double)lbl_803E3F98,afStack_98,0x78);
    dVar2 = (double)DAT_803ad324;
    FUN_80247a7c(dVar2,(double)(float)(dVar2 * (double)DAT_803ad32c),dVar2,afStack_68);
    FUN_80247618(afStack_68,afStack_98,afStack_68);
    FUN_80247a48((double)(DAT_803ad318 - lbl_803DDA58),(double)DAT_803ad31c,
                 (double)(DAT_803ad320 - lbl_803DDA5C),afStack_c8);
    FUN_80247618(afStack_f8,afStack_c8,afStack_f8);
    FUN_80247618(afStack_f8,afStack_68,afStack_38);
    FUN_8025d80c(afStack_38,0);
    FUN_80247618(afStack_f8,afStack_98,afStack_38);
    local_2c = lbl_803E3F4C;
    local_1c = lbl_803E3F4C;
    local_c = lbl_803E3F4C;
    FUN_8025d8c4(afStack_38,0x1e,0);
    FUN_8025d180((double)DAT_803ad328,10,0x14);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016ddd8
 * EN v1.0 Address: 0x8016DDD8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8016E1D8
 * EN v1.1 Size: 692b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016ddd8(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8016dddc
 * EN v1.0 Address: 0x8016DDDC
 * EN v1.0 Size: 2004b
 * EN v1.1 Address: 0x8016E48C
 * EN v1.1 Size: 1780b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016dddc(void)
{
  uint uVar1;
  float fVar2;
  float fVar3;
  bool bVar4;
  int iVar5;
  int extraout_r4;
  int iVar6;
  int *piVar7;
  short *in_r6;
  float *pfVar8;
  float *pfVar9;
  float *pfVar10;
  float *pfVar11;
  float *pfVar12;
  float *pfVar13;
  uint uVar14;
  uint uVar15;
  int iVar16;
  int *piVar17;
  int iVar18;
  double dVar19;
  double dVar20;
  double dVar21;
  double dVar22;
  double dVar23;
  double in_f25;
  double dVar24;
  double in_f26;
  double in_f27;
  double dVar25;
  double in_f28;
  double dVar26;
  double in_f29;
  double in_f30;
  double in_f31;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  float local_138 [4];
  float local_128 [4];
  float local_118 [4];
  float local_108 [4];
  float local_f8 [4];
  float local_e8 [4];
  int local_d8 [4];
  undefined8 local_c8;
  undefined4 local_c0;
  uint uStack_bc;
  undefined8 local_b8;
  undefined8 local_b0;
  undefined8 local_a8;
  undefined4 local_a0;
  uint uStack_9c;
  float local_68;
  float fStack_64;
  float local_58;
  float fStack_54;
  float local_48;
  float fStack_44;
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
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  local_68 = (float)in_f25;
  fStack_64 = (float)in_ps25_1;
  FUN_8028682c();
  if ((*(int *)(extraout_r4 + 0x48) != 0) && (*(char *)(extraout_r4 + 0xbc) == '\0')) {
    iVar6 = (int)*in_r6;
    if (*(short **)(in_r6 + 0x18) != (short *)0x0) {
      iVar6 = iVar6 + **(short **)(in_r6 + 0x18);
    }
    local_c8 = (double)CONCAT44(0x43300000,-iVar6 ^ 0x80000000);
    dVar19 = (double)FUN_80293f90();
    dVar20 = (double)FUN_80294964();
    iVar6 = FUN_80017a54((int)in_r6);
    iVar6 = *(int *)(iVar6 + 0x2c);
    if ((*(int **)(in_r6 + 0x2e) != (int *)0x0) && (0 < **(int **)(in_r6 + 0x2e))) {
      piVar17 = *(int **)(extraout_r4 + 0x48);
      uVar1 = (uint)(lbl_803E3FA4 * *(float *)(iVar6 + 0x14));
      local_c8 = (double)(longlong)(int)uVar1;
      dVar24 = (double)((float)piVar17[2] * *(float *)(iVar6 + 0x14));
      if ((*(byte *)(piVar17 + 5) & 1) != 0) {
        *(undefined4 *)(extraout_r4 + 0x8c) = *(undefined4 *)(in_r6 + 0xc);
        *(undefined4 *)(extraout_r4 + 0x90) = *(undefined4 *)(in_r6 + 0xe);
        *(undefined4 *)(extraout_r4 + 0x94) = *(undefined4 *)(in_r6 + 0x10);
        *(float *)(extraout_r4 + 0x98) = lbl_803E3F4C;
        *(byte *)(piVar17 + 5) = *(byte *)(piVar17 + 5) & 0xfe;
      }
      if (dVar24 < (double)*(float *)(extraout_r4 + 0x98)) {
        *(undefined4 *)(extraout_r4 + 0x98) = *(undefined4 *)(iVar6 + 4);
        goto LAB_8016eb30;
      }
      iVar16 = *(int *)(*(int *)(in_r6 + 0x2e) + 4);
      if ((double)lbl_803E3F4C <= (double)*(float *)(extraout_r4 + 0x98)) {
        dVar21 = (double)FUN_802924c4();
        dVar25 = (double)((float)(dVar21 / (double)lbl_803E3F3C) * lbl_803E3FA4);
        dVar21 = (double)FUN_802924c4();
        dVar26 = (double)((float)(dVar21 / (double)lbl_803E3F3C) * lbl_803E3FA4);
        uVar14 = (uint)dVar25;
        local_c8 = (double)(longlong)(int)uVar14;
        uStack_bc = uVar14 ^ 0x80000000;
        local_c0 = 0x43300000;
        dVar21 = (double)(float)(dVar25 - (double)(float)((double)CONCAT44(0x43300000,
                                                                           uVar14 ^ 0x80000000) -
                                                         DOUBLE_803e3fb0));
        uVar15 = (uint)((float)(dVar26 - dVar25) / lbl_803E3F44);
        local_b8 = (double)(longlong)(int)uVar15;
        if (uVar15 == 0) {
          if (dVar24 < (double)*(float *)(iVar6 + 4)) {
            *(float *)(extraout_r4 + 0x98) = *(float *)(iVar6 + 4);
          }
          goto LAB_8016eb30;
        }
        dVar24 = (double)lbl_803E3F4C;
        local_b8 = (double)CONCAT44(0x43300000,uVar15 ^ 0x80000000);
        dVar25 = (double)(lbl_803E3F20 / (float)(local_b8 - DOUBLE_803e3fb0));
        bVar4 = true;
        while (uVar15 != 0) {
          if (*(short *)((int)piVar17 + 0xe) == 0xbb6) {
            uVar15 = 0;
          }
          else {
            dVar21 = (double)(float)(dVar21 + (double)lbl_803E3F44);
            if ((double)lbl_803E3F20 <= dVar21) {
              dVar21 = (double)(float)(dVar21 - (double)lbl_803E3F20);
              uVar14 = uVar14 + 1;
              bVar4 = true;
            }
            dVar24 = (double)(float)(dVar24 + dVar25);
            if (bVar4) {
              local_d8[0] = uVar14 - 1;
              local_d8[1] = uVar14;
              local_d8[2] = uVar14 + 1;
              local_d8[3] = uVar14 + 2;
              if ((int)(uVar14 - 1) < 0) {
                local_d8[0] = 0;
              }
              if ((int)uVar1 <= (int)uVar14) {
                local_d8[1] = uVar1;
              }
              if ((int)uVar1 <= (int)(uVar14 + 1)) {
                local_d8[2] = uVar1;
              }
              if ((int)uVar1 <= (int)(uVar14 + 2)) {
                local_d8[3] = uVar1;
              }
              piVar7 = local_d8;
              pfVar13 = local_e8;
              pfVar8 = local_f8;
              pfVar9 = local_108;
              pfVar10 = local_118;
              pfVar11 = local_128;
              pfVar12 = local_138;
              iVar18 = 4;
              do {
                iVar5 = *piVar7 * 0xc;
                local_b8 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar16 + iVar5) ^ 0x80000000)
                ;
                *pfVar13 = (float)(local_b8 - DOUBLE_803e3fb0) / lbl_803E3F8C;
                uStack_bc = (int)*(short *)(iVar16 + iVar5 + 2) ^ 0x80000000;
                local_c0 = 0x43300000;
                *pfVar8 = (float)((double)CONCAT44(0x43300000,uStack_bc) - DOUBLE_803e3fb0) /
                          lbl_803E3F8C;
                local_c8 = (double)CONCAT44(0x43300000,
                                            (int)*(short *)(iVar16 + iVar5 + 4) ^ 0x80000000);
                *pfVar9 = (float)(local_c8 - DOUBLE_803e3fb0) / lbl_803E3F8C;
                local_b0 = (double)CONCAT44(0x43300000,
                                            (int)*(short *)(iVar16 + iVar5 + 6) ^ 0x80000000);
                *pfVar10 = (float)(local_b0 - DOUBLE_803e3fb0) / lbl_803E3F8C;
                local_a8 = (double)CONCAT44(0x43300000,
                                            (int)*(short *)(iVar16 + iVar5 + 8) ^ 0x80000000);
                *pfVar11 = (float)(local_a8 - DOUBLE_803e3fb0) / lbl_803E3F8C;
                uStack_9c = (int)*(short *)(iVar16 + iVar5 + 10) ^ 0x80000000;
                local_a0 = 0x43300000;
                *pfVar12 = (float)((double)CONCAT44(0x43300000,uStack_9c) - DOUBLE_803e3fb0) /
                           lbl_803E3F8C;
                fVar2 = *pfVar13;
                fVar3 = *pfVar9;
                *pfVar13 = (float)(dVar20 * (double)fVar2 - (double)(float)(dVar19 * (double)fVar3))
                ;
                *pfVar9 = (float)(dVar19 * (double)fVar2 + (double)(float)(dVar20 * (double)fVar3));
                fVar2 = *pfVar10;
                fVar3 = *pfVar12;
                *pfVar10 = (float)(dVar20 * (double)fVar2 - (double)(float)(dVar19 * (double)fVar3))
                ;
                *pfVar12 = (float)(dVar19 * (double)fVar2 + (double)(float)(dVar20 * (double)fVar3))
                ;
                piVar7 = piVar7 + 1;
                pfVar13 = pfVar13 + 1;
                pfVar8 = pfVar8 + 1;
                pfVar9 = pfVar9 + 1;
                pfVar10 = pfVar10 + 1;
                pfVar11 = pfVar11 + 1;
                pfVar12 = pfVar12 + 1;
                iVar18 = iVar18 + -1;
              } while (iVar18 != 0);
              bVar4 = false;
            }
            pfVar13 = (float *)(*piVar17 + (uint)*(ushort *)((int)piVar17 + 0xe) * 0x14);
            dVar22 = FUN_80006a38(dVar21,local_118,(float *)0x0);
            *pfVar13 = (float)dVar22;
            dVar22 = FUN_80006a38(dVar21,local_128,(float *)0x0);
            pfVar13[1] = (float)dVar22;
            dVar22 = FUN_80006a38(dVar21,local_138,(float *)0x0);
            pfVar13[2] = (float)dVar22;
            *pfVar13 = *pfVar13 +
                       (float)(dVar24 * (double)(float)((double)*(float *)(in_r6 + 0xc) -
                                                       (double)*(float *)(extraout_r4 + 0x8c)) +
                              (double)*(float *)(extraout_r4 + 0x8c));
            pfVar13[1] = pfVar13[1] +
                         (float)(dVar24 * (double)(float)((double)*(float *)(in_r6 + 0xe) -
                                                         (double)*(float *)(extraout_r4 + 0x90)) +
                                (double)*(float *)(extraout_r4 + 0x90));
            pfVar13[2] = pfVar13[2] +
                         (float)(dVar24 * (double)(float)((double)*(float *)(in_r6 + 0x10) -
                                                         (double)*(float *)(extraout_r4 + 0x94)) +
                                (double)*(float *)(extraout_r4 + 0x94));
            uStack_9c = uVar14 ^ 0x80000000;
            local_a0 = 0x43300000;
            fVar2 = (float)((double)(float)((double)CONCAT44(0x43300000,uStack_9c) - DOUBLE_803e3fb0
                                           ) + dVar21);
            dVar22 = (double)fVar2;
            pfVar13[3] = fVar2;
            fVar2 = lbl_803E3F8C * (float)(dVar26 - (double)pfVar13[3]) * lbl_803E3FA8;
            fVar3 = lbl_803E3F4C;
            if ((lbl_803E3F4C <= fVar2) && (fVar3 = fVar2, lbl_803E3F8C < fVar2)) {
              fVar3 = lbl_803E3F8C;
            }
            local_a8 = (double)(longlong)(int)(lbl_803E3F8C - fVar3);
            *(short *)(pfVar13 + 4) = (short)(int)(lbl_803E3F8C - fVar3);
            dVar23 = FUN_80006a38(dVar21,local_e8,(float *)0x0);
            pfVar13[5] = (float)dVar23;
            dVar23 = FUN_80006a38(dVar21,local_f8,(float *)0x0);
            pfVar13[6] = (float)dVar23;
            dVar23 = FUN_80006a38(dVar21,local_108,(float *)0x0);
            pfVar13[7] = (float)dVar23;
            pfVar13[5] = pfVar13[5] +
                         (float)(dVar24 * (double)(float)((double)*(float *)(in_r6 + 0xc) -
                                                         (double)*(float *)(extraout_r4 + 0x8c)) +
                                (double)*(float *)(extraout_r4 + 0x8c));
            pfVar13[6] = pfVar13[6] +
                         (float)(dVar24 * (double)(float)((double)*(float *)(in_r6 + 0xe) -
                                                         (double)*(float *)(extraout_r4 + 0x90)) +
                                (double)*(float *)(extraout_r4 + 0x90));
            pfVar13[7] = pfVar13[7] +
                         (float)(dVar24 * (double)(float)((double)*(float *)(in_r6 + 0x10) -
                                                         (double)*(float *)(extraout_r4 + 0x94)) +
                                (double)*(float *)(extraout_r4 + 0x94));
            pfVar13[8] = (float)dVar22;
            fVar2 = lbl_803E3F8C * (float)(dVar26 - (double)pfVar13[8]) * lbl_803E3FA8;
            fVar3 = lbl_803E3F4C;
            if ((lbl_803E3F4C <= fVar2) && (fVar3 = fVar2, lbl_803E3F8C < fVar2)) {
              fVar3 = lbl_803E3F8C;
            }
            local_b0 = (double)(longlong)(int)(lbl_803E3F8C - fVar3);
            *(short *)(pfVar13 + 9) = (short)(int)(lbl_803E3F8C - fVar3);
            *(short *)((int)piVar17 + 0x12) = *(short *)((int)piVar17 + 0x12) + 2;
            *(short *)((int)piVar17 + 0xe) = *(short *)((int)piVar17 + 0xe) + 2;
            uVar15 = uVar15 - 1;
          }
        }
      }
    }
    *(undefined4 *)(extraout_r4 + 0x8c) = *(undefined4 *)(in_r6 + 0xc);
    *(undefined4 *)(extraout_r4 + 0x90) = *(undefined4 *)(in_r6 + 0xe);
    *(undefined4 *)(extraout_r4 + 0x94) = *(undefined4 *)(in_r6 + 0x10);
    *(undefined4 *)(extraout_r4 + 0x98) = *(undefined4 *)(iVar6 + 4);
  }
LAB_8016eb30:
  FUN_80286878();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016e5b0
 * EN v1.0 Address: 0x8016E5B0
 * EN v1.0 Size: 168b
 * EN v1.1 Address: 0x8016EB80
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016e5b0(uint param_1,char param_2,char param_3)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (param_2 == '\0') {
    if (lbl_803E3F4C < *(float *)(iVar1 + 0x50)) {
      FUN_80006824(param_1,0xc1);
    }
    if (param_3 == '\0') {
      *(float *)(iVar1 + 0x50) = lbl_803E3FBC;
    }
    else {
      *(float *)(iVar1 + 0x50) = lbl_803E3FC0;
    }
  }
  else {
    if (*(float *)(iVar1 + 0x50) < lbl_803E3F4C) {
      FUN_80006824(param_1,0xc0);
    }
    if (param_3 == '\0') {
      *(float *)(iVar1 + 0x50) = lbl_803E3FB8;
    }
    else {
      *(float *)(iVar1 + 0x50) = lbl_803E3F20;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016e658
 * EN v1.0 Address: 0x8016E658
 * EN v1.0 Size: 16b
 * EN v1.1 Address: 0x8016ECC8
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016e658(int param_1)
{
  *(undefined4 *)(*(int *)(param_1 + 0xb8) + 0x48) = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016e668
 * EN v1.0 Address: 0x8016E668
 * EN v1.0 Size: 384b
 * EN v1.1 Address: 0x8016ED7C
 * EN v1.1 Size: 548b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016e668(uint param_1)
{
  int iVar1;
  int iVar2;
  undefined2 local_68;
  undefined2 local_66;
  undefined2 local_64;
  float local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50 [4];
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  
  iVar2 = *(int *)(param_1 + 0x54);
  local_50[0] = DAT_802c29a0;
  local_50[1] = DAT_802c29a4;
  local_50[2] = DAT_802c29a8;
  local_50[3] = DAT_802c29ac;
  local_40 = DAT_802c29b0;
  local_3c = DAT_802c29b4;
  local_38 = DAT_802c29b8;
  local_34 = DAT_802c29bc;
  local_30 = DAT_802c29c0;
  local_2c = DAT_802c29c4;
  local_28 = DAT_802c29c8;
  local_24 = DAT_802c29cc;
  local_20 = DAT_802c29d0;
  local_1c = DAT_802c29d4;
  local_18 = DAT_802c29d8;
  local_14 = DAT_802c29dc;
  FUN_8016ddd8();
  if ((*(char *)(iVar2 + 0xad) != '\0') && (iVar1 = FUN_800176d0(), iVar1 == 0)) {
    iVar1 = (int)*(char *)(iVar2 + 0xac);
    if (iVar1 < 0) {
      iVar1 = 0;
    }
    else if (0x23 < iVar1) {
      iVar1 = 0x23;
    }
    if (iVar1 == 0xe) {
      FUN_80006820((double)*(float *)(iVar2 + 0x3c),(double)*(float *)(iVar2 + 0x40),
                   (double)*(float *)(iVar2 + 0x44),param_1,0xba);
      (**(code **)(*DAT_803dd718 + 0x10))
                ((double)*(float *)(iVar2 + 0x3c),(double)*(float *)(iVar2 + 0x40),
                 (double)*(float *)(iVar2 + 0x44),(double)lbl_803E3F4C,param_1);
      (**(code **)(*DAT_803dd718 + 0x14))
                ((double)*(float *)(iVar2 + 0x3c),(double)*(float *)(iVar2 + 0x40),
                 (double)*(float *)(iVar2 + 0x44),(double)lbl_803E3F4C,0,2);
    }
    else {
      local_60 = lbl_803E3F20;
      local_64 = 0;
      local_66 = 0;
      local_68 = 0;
      local_5c = *(undefined4 *)(iVar2 + 0x3c);
      local_58 = *(undefined4 *)(iVar2 + 0x40);
      local_54 = *(undefined4 *)(iVar2 + 0x44);
      (**(code **)(*DAT_803de720 + 4))
                (0,1,&local_68,0x401,0xffffffff,local_50 + (uint)(byte)(&DAT_80321538)[iVar1] * 4);
      FUN_80006820((double)*(float *)(iVar2 + 0x3c),(double)*(float *)(iVar2 + 0x40),
                   (double)*(float *)(iVar2 + 0x44),param_1,(&DAT_803214f0)[iVar1]);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016e7e8
 * EN v1.0 Address: 0x8016E7E8
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x8016EFA0
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016e7e8(int param_1)
{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  FUN_8016dddc();
  iVar1 = FUN_800176d0();
  if (iVar1 == 0) {
    *(undefined *)(iVar2 + 0xbc) = 0;
  }
  else {
    *(undefined *)(iVar2 + 0xbc) = 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016e834
 * EN v1.0 Address: 0x8016E834
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8016EFFC
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016e834(int param_1)
{
  FUN_8016d188(param_1,*(int *)(param_1 + 0xc4));
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016e858
 * EN v1.0 Address: 0x8016E858
 * EN v1.0 Size: 116b
 * EN v1.1 Address: 0x8016F030
 * EN v1.1 Size: 120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016e858(int param_1)
{
  int iVar1;
  uint *puVar2;
  
  iVar1 = 0;
  puVar2 = *(uint **)(param_1 + 0xb8);
  do {
    FUN_80017814(*puVar2);
    puVar2 = puVar2 + 6;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 3);
  (**(code **)(*DAT_803dd6f8 + 0x18))(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016e8cc
 * EN v1.0 Address: 0x8016E8CC
 * EN v1.0 Size: 1068b
 * EN v1.1 Address: 0x8016F0A8
 * EN v1.1 Size: 756b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016e8cc(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  short sVar1;
  int iVar2;
  int *piVar3;
  uint uVar4;
  int iVar5;
  int *piVar6;
  double dVar7;
  double dVar8;
  undefined8 local_18;
  
  piVar6 = *(int **)(param_9 + 0xb8);
  iVar2 = FUN_80017a54(param_9);
  *(ushort *)(iVar2 + 0x18) = *(ushort *)(iVar2 + 0x18) & 0xfff7;
  FUN_8002fc3c((double)(float)piVar6[0x14],(double)lbl_803DC074);
  iVar2 = 3;
  piVar3 = piVar6;
  do {
    if ((*(byte *)(piVar3 + 5) & 2) != 0) {
      uVar4 = (uint)*(ushort *)(piVar3 + 3);
      iVar5 = *piVar3 + uVar4 * 0x14;
      for (; (int)uVar4 < (int)(uint)*(ushort *)((int)piVar3 + 0xe); uVar4 = uVar4 + 2) {
        if (piVar3 == (int *)piVar6[0x12]) {
          param_3 = (double)lbl_803E3F8C;
          dVar7 = (double)(float)(param_3 *
                                 (double)((lbl_803E3FA4 * (float)piVar6[0x26] -
                                          *(float *)(iVar5 + 0xc)) * lbl_803E3FA8));
          dVar8 = (double)lbl_803E3F4C;
          if ((dVar8 <= dVar7) && (dVar8 = dVar7, param_3 < dVar7)) {
            dVar8 = param_3;
          }
          *(short *)(iVar5 + 0x10) = (short)(int)(param_3 - dVar8);
          *(undefined2 *)(iVar5 + 0x24) = *(undefined2 *)(iVar5 + 0x10);
        }
        else {
          param_3 = (double)lbl_803E3FC4;
          local_18 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar5 + 0x10) ^ 0x80000000);
          *(short *)(iVar5 + 0x10) =
               (short)(int)-(float)(param_3 * (double)lbl_803DC074 -
                                   (double)(float)(local_18 - DOUBLE_803e3fb0));
          *(undefined2 *)(iVar5 + 0x24) = *(undefined2 *)(iVar5 + 0x10);
        }
        sVar1 = *(short *)(iVar5 + 0x10);
        if (sVar1 < 0) {
          sVar1 = 0;
        }
        else if (0xff < sVar1) {
          sVar1 = 0xff;
        }
        *(short *)(iVar5 + 0x10) = sVar1;
        sVar1 = *(short *)(iVar5 + 0x24);
        if (sVar1 < 0) {
          sVar1 = 0;
        }
        else if (0xff < sVar1) {
          sVar1 = 0xff;
        }
        *(short *)(iVar5 + 0x24) = sVar1;
        if ((*(short *)(iVar5 + 0x10) < 1) && (*(short *)(iVar5 + 0x24) < 1)) {
          *(short *)((int)piVar3 + 0x12) = *(short *)((int)piVar3 + 0x12) + -2;
          *(short *)(piVar3 + 3) = *(short *)(piVar3 + 3) + 2;
        }
        iVar5 = iVar5 + 0x28;
      }
      if ((piVar3 != (int *)piVar6[0x12]) && (*(short *)((int)piVar3 + 0x12) == 0)) {
        *(byte *)(piVar3 + 5) = *(byte *)(piVar3 + 5) & 0xfd;
      }
    }
    piVar3 = piVar3 + 6;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  FUN_8016d188(param_9,*(int *)(param_9 + 0xc4));
  FUN_80294d6c(*(int *)(param_9 + 0xc4));
  *(undefined *)((int)piVar6 + 0xb9) = 0;
  if (DAT_803ad338 != '\0') {
    DAT_803ad324 = DAT_803ad324 + lbl_803E3F78;
    FUN_80035b84(DAT_803ad334,(short)(int)DAT_803ad324);
    ObjHits_SetHitVolumeSlot(DAT_803ad334,0x11,5,0);
    DAT_803ad330 = DAT_803ad330 + lbl_803E3F7C;
    dVar8 = (double)DAT_803ad330;
    DAT_803ad328 = DAT_803ad328 * lbl_803E3F80;
    DAT_803ad32c = DAT_803ad32c * lbl_803E3F84;
    *(char *)(DAT_803ad334 + 0x36) = (char)(int)DAT_803ad330;
    *(float *)(DAT_803ad334 + 8) = *(float *)(DAT_803ad334 + 8) + lbl_803E3F88;
    if ((double)DAT_803ad330 < (double)lbl_803E3F20) {
      DAT_803ad338 = '\0';
      FUN_80017ac8((double)DAT_803ad330,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,
                   DAT_803ad334);
      DAT_803ad334 = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016ecf8
 * EN v1.0 Address: 0x8016ECF8
 * EN v1.0 Size: 180b
 * EN v1.1 Address: 0x8016F39C
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016ecf8(int param_1)
{
  int iVar1;
  int *piVar2;
  int iVar3;
  
  piVar2 = *(int **)(param_1 + 0xb8);
  *(undefined *)((int)piVar2 + 0xaa) = 1;
  *(undefined2 *)(piVar2 + 0x2c) = 2;
  piVar2[0x14] = (int)lbl_803E3FC0;
  if (*(int *)(param_1 + 0x54) != 0) {
    *(undefined2 *)(*(int *)(param_1 + 0x54) + 0xb2) = 0x109;
  }
  iVar3 = 0;
  do {
    iVar1 = FUN_80017830(60000,0x1a);
    *piVar2 = iVar1;
    *(undefined2 *)(piVar2 + 4) = 0xffff;
    piVar2 = piVar2 + 6;
    iVar3 = iVar3 + 1;
  } while (iVar3 < 3);
  DAT_803ad338 = 0;
  DAT_803ad334 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016edac
 * EN v1.0 Address: 0x8016EDAC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8016F454
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016edac(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8016edb0
 * EN v1.0 Address: 0x8016EDB0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8016F4D4
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016edb0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8016edb4
 * EN v1.0 Address: 0x8016EDB4
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8016F618
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_8016edb4(int param_1)
{
  return *(undefined *)(*(int *)(param_1 + 0xb8) + 0x71);
}

/*
 * --INFO--
 *
 * Function: FUN_8016edc0
 * EN v1.0 Address: 0x8016EDC0
 * EN v1.0 Size: 216b
 * EN v1.1 Address: 0x8016F624
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8016edc0(int param_1,undefined4 param_2,int param_3)
{
  char cVar1;
  int *piVar2;
  int iVar3;
  
  piVar2 = *(int **)(param_1 + 0xb8);
  if ((*(byte *)(piVar2 + 0x1c) & 8) == 0) {
    for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
      cVar1 = *(char *)(param_3 + iVar3 + 0x81);
      if (cVar1 == '\x01') {
        if (*piVar2 != 0) {
          FUN_800175cc((double)lbl_803E3FC8,*piVar2,'\x01');
        }
        *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xbfff;
      }
      else if (cVar1 == '\x02') {
        if (*piVar2 != 0) {
          FUN_800175cc((double)lbl_803E3FC8,*piVar2,'\0');
        }
        *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
      }
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8016ee98
 * EN v1.0 Address: 0x8016EE98
 * EN v1.0 Size: 416b
 * EN v1.1 Address: 0x8016F70C
 * EN v1.1 Size: 764b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016ee98(int param_1,int param_2,int param_3)
{
  float fVar1;
  float *pfVar2;
  double dVar3;
  double dVar4;
  
  pfVar2 = (float *)(*(int *)(param_3 + 0x74) + (uint)*(byte *)(param_3 + 0xe4) * 0x18);
  if (pfVar2 != (float *)0x0) {
    dVar4 = (double)(*pfVar2 - *(float *)(param_2 + 0x24));
    dVar3 = (double)(pfVar2[2] - *(float *)(param_2 + 0x2c));
    FUN_80017730();
    FUN_80293900((double)(*(float *)(param_1 + 0x24) * *(float *)(param_1 + 0x24) +
                         *(float *)(param_1 + 0x2c) * *(float *)(param_1 + 0x2c)));
    FUN_80017730();
    FUN_80017730();
    FUN_80293900((double)(float)(dVar4 * dVar4 + (double)(float)(dVar3 * dVar3)));
    FUN_80017730();
    dVar3 = (double)FUN_80293f90();
    *(float *)(param_1 + 0x24) = (float)dVar3;
    dVar3 = (double)FUN_80294964();
    *(float *)(param_1 + 0x2c) = (float)dVar3;
    dVar3 = (double)FUN_80293f90();
    dVar4 = (double)FUN_80294964();
    if ((double)lbl_803E3FC8 != dVar4) {
      dVar3 = (double)(float)(dVar3 / dVar4);
    }
    *(float *)(param_1 + 0x28) = (float)dVar3;
    dVar3 = FUN_80293900((double)(*(float *)(param_1 + 0x2c) * *(float *)(param_1 + 0x2c) +
                                 *(float *)(param_1 + 0x24) * *(float *)(param_1 + 0x24) +
                                 *(float *)(param_1 + 0x28) * *(float *)(param_1 + 0x28)));
    fVar1 = (float)((double)lbl_803E3FD8 / dVar3);
    *(float *)(param_1 + 0x24) = *(float *)(param_1 + 0x24) * fVar1;
    *(float *)(param_1 + 0x28) = *(float *)(param_1 + 0x28) * fVar1;
    *(float *)(param_1 + 0x2c) = *(float *)(param_1 + 0x2c) * fVar1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016f038
 * EN v1.0 Address: 0x8016F038
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x8016FA08
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016f038(int param_1)
{
  if (**(uint **)(param_1 + 0xb8) != 0) {
    FUN_80017620(**(uint **)(param_1 + 0xb8));
  }
  (**(code **)(*DAT_803dd6f8 + 0x18))(param_1);
  ObjGroup_RemoveObject(param_1,2);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016f09c
 * EN v1.0 Address: 0x8016F09C
 * EN v1.0 Size: 512b
 * EN v1.1 Address: 0x8016FA68
 * EN v1.1 Size: 568b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016f09c(void)
{
  undefined2 uVar1;
  undefined2 uVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  char in_r8;
  uint uVar6;
  byte bVar7;
  int *piVar8;
  double dVar9;
  
  iVar3 = FUN_8028682c();
  piVar8 = *(int **)(iVar3 + 0xb8);
  if (((in_r8 != '\0') && ((*(byte *)(piVar8 + 0x1c) & 8) == 0)) &&
     ((float)piVar8[0xf] == lbl_803E3FC8)) {
    *(undefined *)(iVar3 + 0xad) = 1;
    iVar4 = FUN_80017a54(iVar3);
    *(undefined *)(*(int *)(iVar4 + 0x34) + 8) = (&DAT_803dc9c0)[*(byte *)((int)piVar8 + 0x71)];
    uVar1 = *(undefined2 *)(iVar3 + 4);
    uVar2 = *(undefined2 *)(iVar3 + 2);
    dVar9 = (double)*(float *)(iVar3 + 8);
    *(float *)(iVar3 + 8) = lbl_803E3FE8;
    for (bVar7 = 0; bVar7 < 5; bVar7 = bVar7 + 1) {
      *(short *)((int)piVar8 + (uint)bVar7 * 2 + 0x48) =
           *(short *)((int)piVar8 + (uint)bVar7 * 2 + 0x48) +
           *(short *)((int)piVar8 + (uint)bVar7 * 2 + 0x52);
      *(short *)((int)piVar8 + (uint)bVar7 * 2 + 0x5c) =
           *(short *)((int)piVar8 + (uint)bVar7 * 2 + 0x5c) +
           *(short *)((int)piVar8 + (uint)bVar7 * 2 + 0x66);
      *(undefined2 *)(iVar3 + 4) = *(undefined2 *)((int)piVar8 + (uint)bVar7 * 2 + 0x48);
      *(undefined2 *)(iVar3 + 2) = *(undefined2 *)((int)piVar8 + (uint)bVar7 * 2 + 0x5c);
      *(ushort *)(iVar4 + 0x18) = *(ushort *)(iVar4 + 0x18) & 0xfff7;
      FUN_8003b818(iVar3);
    }
    *(undefined2 *)(iVar3 + 4) = uVar1;
    *(undefined2 *)(iVar3 + 2) = uVar2;
    *(float *)(iVar3 + 8) = (float)dVar9;
    *(undefined *)(iVar3 + 0xad) = 0;
    iVar4 = FUN_80017a54(iVar3);
    *(undefined *)(*(int *)(iVar4 + 0x34) + 8) = (&DAT_803dc9c0)[*(byte *)((int)piVar8 + 0x71)];
    FUN_8003b818(iVar3);
    iVar3 = *piVar8;
    if (iVar3 != 0) {
      if ((*(char *)(iVar3 + 0x2f8) != '\0') && (*(char *)(iVar3 + 0x4c) != '\0')) {
        uVar6 = (uint)*(byte *)(iVar3 + 0x2f9) + (int)*(char *)(iVar3 + 0x2fa) & 0xffff;
        if (0xc < uVar6) {
          uVar5 = FUN_80017760(0xfffffff4,0xc);
          uVar6 = uVar6 + uVar5 & 0xffff;
          if (0xff < uVar6) {
            uVar6 = 0xff;
            *(undefined *)(*piVar8 + 0x2fa) = 0;
          }
        }
        *(char *)(*piVar8 + 0x2f9) = (char)uVar6;
      }
      iVar3 = *piVar8;
      if ((*(char *)(iVar3 + 0x2f8) != '\0') && (*(char *)(iVar3 + 0x4c) != '\0')) {
        FUN_8005fe14(iVar3);
      }
    }
  }
  FUN_80286878();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016f29c
 * EN v1.0 Address: 0x8016F29C
 * EN v1.0 Size: 316b
 * EN v1.1 Address: 0x8016FCA0
 * EN v1.1 Size: 320b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016f29c(int param_1)
{
  int iVar1;
  uint *puVar2;
  
  puVar2 = *(uint **)(param_1 + 0xb8);
  if (((*(short *)(param_1 + 0x46) != 0x83e) && ((*(byte *)(puVar2 + 0x1c) & 8) == 0)) &&
     (iVar1 = *(int *)(*(int *)(param_1 + 0x54) + 0x50), iVar1 != 0)) {
    if (*(short *)(iVar1 + 0x46) == 0x6e8) {
      iVar1 = FUN_8020a8c8(iVar1);
      if ((char)iVar1 != -1) {
        *(char *)((int)puVar2 + 0x71) = (char)iVar1;
        if (*puVar2 != 0) {
          iVar1 = (uint)*(byte *)((int)puVar2 + 0x71) * 3;
          FUN_8001759c(*puVar2,(&DAT_803215c8)[iVar1],(&DAT_803215c9)[iVar1],(&DAT_803215ca)[iVar1],
                       0);
        }
      }
      ObjHits_EnableObject(param_1);
    }
    else {
      puVar2[0xe] = (uint)lbl_803E3FF0;
      if (*(char *)((int)puVar2 + 0x71) == '\0') {
        FUN_80081114(param_1,3);
      }
      else if (*(char *)((int)puVar2 + 0x71) == '\x01') {
        FUN_80081114(param_1,0);
      }
      else {
        FUN_80081114(param_1,6);
      }
      *(undefined *)(param_1 + 0x36) = 0;
      if (*puVar2 != 0) {
        FUN_80017620(*puVar2);
        *puVar2 = 0;
      }
    }
    ObjGroup_RemoveObject(param_1,2);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016f3d8
 * EN v1.0 Address: 0x8016F3D8
 * EN v1.0 Size: 2132b
 * EN v1.1 Address: 0x8016FDE0
 * EN v1.1 Size: 1196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016f3d8(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9)
{
  float fVar1;
  uint uVar2;
  undefined uVar3;
  int iVar4;
  int iVar5;
  uint *puVar6;
  double dVar7;
  double dVar8;
  float local_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  puVar6 = *(uint **)(param_9 + 0x5c);
  iVar5 = *(int *)(param_9 + 0x7c);
  iVar4 = *(int *)(param_9 + 0x26);
  if ((*(byte *)(puVar6 + 0x1c) & 8) == 0) {
    puVar6[0xf] = (uint)((float)puVar6[0xf] - lbl_803DC074);
    if ((float)puVar6[0xf] < lbl_803E3FC8) {
      puVar6[0xf] = (uint)lbl_803E3FC8;
    }
    if (param_9[0x23] == 0x83e) {
      if (*puVar6 != 0) {
        FUN_800175cc((double)lbl_803E3FC8,*puVar6,'\0');
      }
      param_9[3] = param_9[3] | 0x4000;
    }
    else {
      if (lbl_803E3FC8 == (float)puVar6[0xd]) {
        dVar7 = (double)FUN_8001778c((float *)(param_9 + 0x12));
        puVar6[0xc] = (uint)(float)((double)lbl_803E3FF4 / dVar7);
      }
      puVar6[0xd] = (uint)((float)puVar6[0xd] + lbl_803DC074);
      if ((float)puVar6[0xc] < (float)puVar6[0xd]) {
        if (*(char *)(iVar4 + 0x19) == '\0') {
          uVar3 = 1;
        }
        else {
          uVar3 = 3;
        }
        ObjHits_SetHitVolumeSlot((int)param_9,0xe,uVar3,0);
      }
      if ((*(byte *)(puVar6 + 0x1c) & 1) == 0) {
        puVar6[9] = *(uint *)(param_9 + 6);
        puVar6[10] = *(uint *)(param_9 + 8);
        puVar6[0xb] = *(uint *)(param_9 + 10);
        *(byte *)(puVar6 + 0x1c) = *(byte *)(puVar6 + 0x1c) | 1;
      }
      if (*(char *)(*(int *)(param_9 + 0x2a) + 0xad) != '\0') {
        if (*(char *)(*(int *)(param_9 + 0x2a) + 0xac) == '\x0e') {
          FUN_80006824((uint)param_9,0xba);
          (**(code **)(*DAT_803dd718 + 0x10))
                    ((double)*(float *)(param_9 + 6),(double)*(float *)(param_9 + 8),
                     (double)*(float *)(param_9 + 10),(double)lbl_803E3FF8,param_9);
          param_2 = (double)*(float *)(param_9 + 8);
          param_3 = (double)*(float *)(param_9 + 10);
          param_4 = (double)lbl_803E3FC8;
          (**(code **)(*DAT_803dd718 + 0x14))((double)*(float *)(param_9 + 6),(int)*param_9,2);
        }
        else {
          FUN_80006824((uint)param_9,0xb3);
        }
        if (*(char *)((int)puVar6 + 0x71) == '\0') {
          FUN_80081114(param_9,3);
        }
        else if (*(char *)((int)puVar6 + 0x71) == '\x01') {
          FUN_80081114(param_9,0);
        }
        else {
          FUN_80081114(param_9,6);
        }
        puVar6[0xe] = (uint)lbl_803E3FF0;
        *(undefined *)(param_9 + 0x1b) = 0;
        if (*puVar6 != 0) {
          FUN_80017620(*puVar6);
          *puVar6 = 0;
        }
        ObjGroup_RemoveObject((int)param_9,2);
        ObjHits_DisableObject((int)param_9);
      }
      fVar1 = lbl_803E3FC8;
      if ((float)puVar6[0xe] == lbl_803E3FC8) {
        *(undefined4 *)(param_9 + 0x40) = *(undefined4 *)(param_9 + 6);
        *(undefined4 *)(param_9 + 0x42) = *(undefined4 *)(param_9 + 8);
        *(undefined4 *)(param_9 + 0x44) = *(undefined4 *)(param_9 + 10);
        if (iVar5 != 0) {
          if ((*(ushort *)(iVar5 + 0xb0) & 0x40) == 0) {
            FUN_8016ee98((int)param_9,(int)puVar6,iVar5);
          }
          else {
            param_9[0x7c] = 0;
            param_9[0x7d] = 0;
          }
        }
        puVar6[9] = (uint)(*(float *)(param_9 + 0x12) * lbl_803DC074 + (float)puVar6[9]);
        puVar6[10] = (uint)(*(float *)(param_9 + 0x14) * lbl_803DC074 + (float)puVar6[10]);
        dVar8 = (double)*(float *)(param_9 + 0x16);
        dVar7 = (double)lbl_803DC074;
        puVar6[0xb] = (uint)(float)(dVar8 * dVar7 + (double)(float)puVar6[0xb]);
        *(ushort *)((int)puVar6 + 0x46) =
             *(short *)((int)puVar6 + 0x46) + (ushort)DAT_803dc070 * 0x5dc;
        if ((*(byte *)(puVar6 + 0x1c) & 4) != 0) {
          puVar6[10] = (uint)-(lbl_803E3FFC * lbl_803DC074 - (float)puVar6[10]);
          dVar7 = (double)(float)puVar6[9];
          dVar8 = (double)(float)puVar6[10];
          param_3 = (double)(float)puVar6[0xb];
          iVar4 = FUN_800632e8(dVar7,dVar8,param_3,param_9,local_28,0);
          if (iVar4 == 0) {
            local_28[0] = local_28[0] - lbl_803E4000;
            dVar7 = (double)local_28[0];
            if ((dVar7 < (double)lbl_803E3FC8) && ((double)lbl_803E4004 < dVar7)) {
              puVar6[10] = (uint)(float)((double)(float)puVar6[10] - dVar7);
            }
          }
        }
        *(uint *)(param_9 + 6) = puVar6[9];
        *(uint *)(param_9 + 8) = puVar6[10];
        *(uint *)(param_9 + 10) = puVar6[0xb];
        if (iVar5 != 0) {
          uStack_1c = (uint)*(ushort *)((int)puVar6 + 0x46);
          local_20 = 0x43300000;
          dVar7 = (double)FUN_80293f90();
          *(float *)(param_9 + 6) =
               (float)((double)lbl_803E3FCC * dVar7 + (double)*(float *)(param_9 + 6));
          uStack_14 = (uint)*(ushort *)((int)puVar6 + 0x46);
          local_18 = 0x43300000;
          dVar7 = (double)FUN_80294964();
          dVar8 = (double)lbl_803E3FCC;
          *(float *)(param_9 + 10) = (float)(dVar8 * dVar7 + (double)*(float *)(param_9 + 10));
        }
        uVar2 = (uint)DAT_803dc070;
        iVar4 = *(int *)(param_9 + 0x7a);
        *(uint *)(param_9 + 0x7a) = iVar4 - uVar2;
        if ((int)(iVar4 - uVar2) < 0) {
          FUN_80017ac8(dVar7,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
        }
      }
      else {
        *(float *)(param_9 + 0x12) = lbl_803E3FC8;
        *(float *)(param_9 + 0x14) = fVar1;
        *(float *)(param_9 + 0x16) = fVar1;
        ObjHits_ClearHitVolumes((int)param_9);
        puVar6[0xe] = (uint)((float)puVar6[0xe] - lbl_803DC074);
        if ((double)(float)puVar6[0xe] <= (double)lbl_803E3FC8) {
          FUN_80017ac8((double)(float)puVar6[0xe],param_2,param_3,param_4,param_5,param_6,param_7,
                       param_8,(int)param_9);
        }
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016fc2c
 * EN v1.0 Address: 0x8016FC2C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017028C
 * EN v1.1 Size: 612b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016fc2c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8016fc30
 * EN v1.0 Address: 0x8016FC30
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x801704F0
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016fc30(int param_1)
{
  FUN_8003b818(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016fc50
 * EN v1.0 Address: 0x8016FC50
 * EN v1.0 Size: 520b
 * EN v1.1 Address: 0x80170518
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016fc50(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  undefined8 uVar5;
  
  iVar4 = *(int *)(param_9 + 0x5c);
  iVar3 = *(int *)(param_9 + 0x26);
  iVar1 = *(int *)(iVar4 + 0x10);
  if (iVar1 == 2) {
    iVar1 = FUN_8007f764((float *)(iVar4 + 4));
    if (iVar1 == 0) {
      ObjHits_EnableObject((int)param_9);
      ObjHits_SetHitVolumeSlot((int)param_9,(char)*(undefined4 *)(&DAT_80321618 + *(char *)(iVar3 + 0x19) * 0xc)
                   ,1,0);
      FUN_80017a88((double)(*(float *)(param_9 + 0x12) * lbl_803DC074),
                   (double)(*(float *)(param_9 + 0x14) * lbl_803DC074),
                   (double)(*(float *)(param_9 + 0x16) * lbl_803DC074),(int)param_9);
      FUN_80035b84((int)param_9,
                   (short)(int)(*(float *)(iVar4 + 0xc) *
                               (((float)((double)CONCAT44(0x43300000,DAT_803dc9cc ^ 0x80000000) -
                                        DOUBLE_803e4030) - *(float *)(iVar4 + 4)) /
                               (float)((double)CONCAT44(0x43300000,DAT_803dc9cc ^ 0x80000000) -
                                      DOUBLE_803e4030))));
    }
    else {
      uVar5 = ObjHits_DisableObject((int)param_9);
      FUN_8020a3f8(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
    }
  }
  else if ((iVar1 < 2) && (0 < iVar1)) {
    *(float *)(param_9 + 0x12) = lbl_803E4024;
    uVar2 = FUN_80017760(100,0x96);
    *(float *)(param_9 + 0x16) =
         lbl_803DC9D0 *
         lbl_803E4028 *
         *(float *)(iVar4 + 8) *
         lbl_803E402C * (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e4030)
    ;
    FUN_80017748(param_9,(float *)(param_9 + 0x12));
    *(float *)(iVar4 + 0xc) = lbl_803DC9D4 * *(float *)(iVar4 + 8);
    FUN_8007f718((float *)(iVar4 + 4),(short)DAT_803dc9cc);
    *(undefined4 *)(iVar4 + 0x10) = 2;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016fe58
 * EN v1.0 Address: 0x8016FE58
 * EN v1.0 Size: 156b
 * EN v1.1 Address: 0x801706D4
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016fe58(int param_1,int param_2)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  FUN_8007f6e4((undefined4 *)(iVar1 + 4));
  *(float *)(iVar1 + 8) =
       ((float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000) -
               DOUBLE_803e4030) / lbl_803E4038) * lbl_803DC9C8;
  *(float *)(param_1 + 0x28) = lbl_803E4024;
  *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
  *(undefined4 *)(iVar1 + 0x10) = 1;
  ObjHits_DisableObject(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016fef4
 * EN v1.0 Address: 0x8016FEF4
 * EN v1.0 Size: 340b
 * EN v1.1 Address: 0x80170780
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8016fef4(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
                undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9)
{
  uint uVar1;
  int iVar2;
  undefined2 *puVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  double dVar4;
  
  dVar4 = param_1;
  uVar1 = FUN_80017ae8();
  if ((uVar1 & 0xff) == 0) {
    iVar2 = 0;
  }
  else {
    puVar3 = FUN_80017aa4(0x24,0x836);
    *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(param_9 + 0x18);
    *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(param_9 + 0x1c);
    *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(param_9 + 0x20);
    *(undefined *)(puVar3 + 2) = 1;
    *(undefined *)((int)puVar3 + 5) = 1;
    *(undefined *)((int)puVar3 + 7) = 0xff;
    iVar2 = FUN_80017ae4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,
                         0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    if (iVar2 != 0) {
      *(float *)(iVar2 + 8) = (float)dVar4;
    }
  }
  return iVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_80170048
 * EN v1.0 Address: 0x80170048
 * EN v1.0 Size: 2352b
 * EN v1.1 Address: 0x8017082C
 * EN v1.1 Size: 1804b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80170048(void)
{
  float fVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  uint uVar5;
  int iVar6;
  int *piVar7;
  int *piVar8;
  float *pfVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  undefined8 uVar15;
  undefined8 local_78;
  undefined8 local_70;
  
  uVar15 = FUN_80286838();
  uVar2 = (uint)((ulonglong)uVar15 >> 0x20);
  pfVar9 = (float *)&DAT_80321678;
  piVar7 = *(int **)(uVar2 + 0xb8);
  iVar3 = FUN_80017a98();
  iVar6 = 0;
  if (iVar3 != 0) {
    iVar6 = FUN_80294cf8(iVar3);
  }
  fVar1 = lbl_803E4064;
  switch((uint)uVar15 & 0xff) {
  case 0:
    if (*piVar7 != 0) {
      FUN_800175cc((double)lbl_803E4040,*piVar7,'\0');
    }
    fVar1 = lbl_803E4048;
    if (lbl_803E4044 != (float)piVar7[2]) {
      piVar7[4] = (int)lbl_803E4048;
      piVar7[1] = (int)fVar1;
      if (iVar6 != 0) {
        FUN_8016d994(iVar6,7,0);
      }
    }
    piVar7[2] = (int)lbl_803E4044;
    piVar7[3] = (int)lbl_803E404C;
    FUN_80006810(uVar2,0x42c);
    FUN_80006810(uVar2,0x42d);
    break;
  case 1:
    if (lbl_803E4044 == (float)piVar7[2]) {
      if (iVar6 != 0) {
        FUN_8016d994(iVar6,7,8);
      }
      if (*piVar7 == 0) {
        piVar4 = FUN_80017624(0,'\x01');
        *piVar7 = (int)piVar4;
      }
      if (*piVar7 != 0) {
        FUN_800175b0(*piVar7,2);
        FUN_800175ec((double)*(float *)(uVar2 + 0xc),
                     (double)(*(float *)(uVar2 + 0x10) - lbl_803E4050),
                     (double)*(float *)(uVar2 + 0x14),(int *)*piVar7);
        FUN_8001759c(*piVar7,0,0xff,0xff,0xff);
        FUN_80017588(*piVar7,0,0xff,0xff,0xff);
        FUN_800175d0((double)lbl_803E4054,(double)lbl_803E4058,*piVar7);
        FUN_800175bc(*piVar7,1);
        FUN_800175cc((double)lbl_803E4044,*piVar7,'\x01');
        FUN_8001753c(*piVar7,0,0);
        FUN_800175d8(*piVar7,1);
      }
      fVar1 = lbl_803E4044;
      if (lbl_803E4044 == (float)piVar7[2]) {
        piVar7[4] = (int)lbl_803E4048;
        piVar7[1] = (int)fVar1;
      }
      piVar7[2] = (int)lbl_803E4048;
      dVar12 = (double)lbl_803E405C;
      piVar7[3] = (int)lbl_803E405C;
      iVar3 = 0;
      piVar8 = &DAT_80321688;
      dVar11 = (double)lbl_803E4040;
      dVar14 = (double)lbl_803E4060;
      piVar4 = piVar7;
      dVar13 = DOUBLE_803e4068;
      do {
        *(undefined2 *)(piVar4 + 0xd) = 0xc000;
        dVar10 = (double)FUN_8029397c();
        piVar7[9] = (int)(*pfVar9 * (float)((double)(float)(dVar12 + dVar10) * dVar11));
        piVar7[5] = *piVar8;
        uVar5 = FUN_80017760(0x78,0x7f);
        local_78 = (double)CONCAT44(0x43300000,iVar3 * uVar5 ^ 0x80000000);
        *(short *)(piVar4 + 0xf) = (short)(int)(dVar14 + (double)(float)(local_78 - dVar13));
        piVar4 = (int *)((int)piVar4 + 2);
        pfVar9 = pfVar9 + 1;
        piVar7 = piVar7 + 1;
        piVar8 = piVar8 + 1;
        iVar3 = iVar3 + 1;
      } while (iVar3 < 4);
      FUN_80006824(uVar2,0x42c);
      FUN_80006824(uVar2,0x42d);
    }
    break;
  case 2:
    if (iVar6 != 0) {
      FUN_8016d994(iVar6,7,0);
    }
    if (lbl_803E4044 != (float)piVar7[2]) {
      piVar7[4] = (int)lbl_803E4064;
    }
    piVar7[2] = (int)lbl_803E4044;
    piVar7[3] = (int)lbl_803E404C;
    if (*piVar7 != 0) {
      FUN_800175cc((double)lbl_803E4040,*piVar7,'\0');
    }
    FUN_80006810(uVar2,0x42c);
    FUN_80006810(uVar2,0x42d);
    break;
  case 3:
    if (iVar6 != 0) {
      FUN_8016d994(iVar6,7,8);
    }
    if (*piVar7 == 0) {
      piVar4 = FUN_80017624(0,'\x01');
      *piVar7 = (int)piVar4;
    }
    if (*piVar7 != 0) {
      FUN_800175b0(*piVar7,2);
      FUN_800175ec((double)*(float *)(uVar2 + 0xc),
                   (double)(*(float *)(uVar2 + 0x10) - lbl_803E4050),
                   (double)*(float *)(uVar2 + 0x14),(int *)*piVar7);
      FUN_8001759c(*piVar7,0,0xff,0xff,0xff);
      FUN_80017588(*piVar7,0,0xff,0xff,0xff);
      FUN_800175d0((double)lbl_803E4054,(double)lbl_803E4058,*piVar7);
      FUN_800175bc(*piVar7,1);
      FUN_800175cc((double)lbl_803E4044,*piVar7,'\x01');
      FUN_8001753c(*piVar7,0,0);
      FUN_800175d8(*piVar7,1);
    }
    if (lbl_803E4044 == (float)piVar7[2]) {
      piVar7[4] = (int)lbl_803E4064;
    }
    piVar7[2] = (int)lbl_803E4064;
    dVar14 = (double)lbl_803E405C;
    piVar7[3] = (int)lbl_803E405C;
    iVar3 = 0;
    piVar8 = &DAT_80321688;
    dVar13 = (double)lbl_803E4040;
    piVar4 = piVar7;
    do {
      *(undefined2 *)(piVar7 + 0xd) = 0;
      dVar11 = (double)FUN_8029397c();
      piVar4[9] = (int)(*pfVar9 * (float)((double)(float)(dVar14 + dVar11) * dVar13));
      piVar4[5] = *piVar8;
      piVar7 = (int *)((int)piVar7 + 2);
      pfVar9 = pfVar9 + 1;
      piVar4 = piVar4 + 1;
      piVar8 = piVar8 + 1;
      iVar3 = iVar3 + 1;
    } while (iVar3 < 4);
    FUN_80006824(uVar2,0x42d);
    FUN_80006824(uVar2,0x42c);
    break;
  case 4:
    piVar7[2] = (int)lbl_803E4064;
    dVar14 = (double)lbl_803E405C;
    piVar7[3] = (int)lbl_803E405C;
    piVar7[4] = (int)fVar1;
    iVar3 = 0;
    pfVar9 = (float *)&DAT_80321698;
    piVar8 = &DAT_803216a8;
    dVar11 = (double)lbl_803E4040;
    dVar12 = (double)lbl_803E4060;
    piVar4 = piVar7;
    dVar13 = DOUBLE_803e4068;
    do {
      *(undefined2 *)(piVar7 + 0xd) = 0xc000;
      dVar10 = (double)FUN_8029397c();
      piVar4[9] = (int)(*pfVar9 * (float)((double)(float)(dVar14 + dVar10) * dVar11));
      piVar4[5] = *piVar8;
      uVar5 = FUN_80017760(0x78,0x7f);
      local_70 = (double)CONCAT44(0x43300000,iVar3 * uVar5 ^ 0x80000000);
      *(short *)(piVar7 + 0xf) = (short)(int)(dVar12 + (double)(float)(local_70 - dVar13));
      piVar7 = (int *)((int)piVar7 + 2);
      pfVar9 = pfVar9 + 1;
      piVar4 = piVar4 + 1;
      piVar8 = piVar8 + 1;
      iVar3 = iVar3 + 1;
    } while (iVar3 < 4);
    FUN_80006824(uVar2,0x42d);
    FUN_80006824(uVar2,0x42c);
    break;
  case 5:
    piVar7[2] = (int)lbl_803E4044;
    piVar7[3] = (int)lbl_803E404C;
    piVar7[4] = (int)lbl_803E4064;
    FUN_80006810(uVar2,0x42c);
    FUN_80006810(uVar2,0x42d);
    break;
  case 6:
    iVar3 = 0;
    pfVar9 = (float *)&DAT_80321698;
    piVar8 = &DAT_803216a8;
    dVar13 = (double)lbl_803E405C;
    dVar14 = (double)lbl_803E4040;
    piVar4 = piVar7;
    do {
      *(undefined2 *)(piVar7 + 0xd) = 0x4000;
      dVar11 = (double)FUN_8029397c();
      piVar4[9] = (int)(*pfVar9 * (float)((double)(float)(dVar13 + dVar11) * dVar14));
      piVar4[5] = *piVar8;
      piVar7 = (int *)((int)piVar7 + 2);
      pfVar9 = pfVar9 + 1;
      piVar4 = piVar4 + 1;
      piVar8 = piVar8 + 1;
      iVar3 = iVar3 + 1;
    } while (iVar3 < 4);
    break;
  case 7:
    if (iVar6 != 0) {
      FUN_8016d994(iVar6,7,0);
    }
    if (*piVar7 != 0) {
      FUN_800175cc((double)lbl_803E4040,*piVar7,'\0');
    }
    fVar1 = lbl_803E4044;
    piVar7[2] = (int)lbl_803E4044;
    piVar7[3] = (int)fVar1;
    piVar7[4] = (int)fVar1;
    piVar7[1] = (int)fVar1;
    *(byte *)(piVar7 + 0x17) = *(byte *)(piVar7 + 0x17) | 1;
    *(byte *)((int)piVar7 + 0x5d) = *(byte *)((int)piVar7 + 0x5d) | 1;
    *(byte *)((int)piVar7 + 0x5e) = *(byte *)((int)piVar7 + 0x5e) | 1;
    *(byte *)((int)piVar7 + 0x5f) = *(byte *)((int)piVar7 + 0x5f) | 1;
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80170978
 * EN v1.0 Address: 0x80170978
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x80170F38
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80170978(int param_1)
{
  uint uVar1;
  uint *puVar2;
  
  puVar2 = *(uint **)(param_1 + 0xb8);
  uVar1 = *puVar2;
  if (uVar1 != 0) {
    FUN_80017620(uVar1);
    *puVar2 = 0;
  }
  FUN_80006810(param_1,0x42c);
  FUN_80006810(param_1,0x42d);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801709dc
 * EN v1.0 Address: 0x801709DC
 * EN v1.0 Size: 1048b
 * EN v1.1 Address: 0x80170F9C
 * EN v1.1 Size: 1152b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801709dc(void)
{
  byte bVar1;
  float fVar2;
  ushort uVar3;
  ushort uVar4;
  ushort uVar5;
  uint uVar6;
  ushort *puVar7;
  int iVar8;
  uint uVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  char in_r8;
  byte bVar13;
  byte bVar14;
  uint uVar15;
  int iVar16;
  double in_f26;
  double dVar17;
  double in_f27;
  double dVar18;
  double in_f28;
  double dVar19;
  double in_f29;
  double dVar20;
  double in_f30;
  double dVar21;
  double in_f31;
  double dVar22;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined auStack_118 [8];
  float local_110;
  float local_10c;
  float local_108;
  float local_104;
  undefined4 local_100;
  uint uStack_fc;
  undefined4 local_f8;
  uint uStack_f4;
  longlong local_f0;
  undefined4 local_e8;
  uint uStack_e4;
  undefined4 local_e0;
  uint uStack_dc;
  longlong local_d8;
  undefined8 local_d0;
  undefined4 local_c8;
  uint uStack_c4;
  longlong local_c0;
  undefined4 local_b8;
  uint uStack_b4;
  undefined8 local_b0;
  float local_58;
  float fStack_54;
  float local_48;
  float fStack_44;
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
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  puVar7 = (ushort *)FUN_80286814();
  iVar16 = *(int *)(puVar7 + 0x5c);
  if (in_r8 != '\0') {
    iVar8 = FUN_80017a54((int)puVar7);
    dVar22 = (double)*(float *)(puVar7 + 4);
    bVar1 = *(byte *)(puVar7 + 0x1b);
    uVar15 = (uint)bVar1;
    uVar3 = *puVar7;
    uVar4 = puVar7[1];
    uVar5 = puVar7[2];
    uVar9 = FUN_800176d0();
    fVar2 = lbl_803DC074;
    if ((uVar9 & 0xff) != 0) {
      fVar2 = lbl_803E4044;
    }
    dVar21 = (double)fVar2;
    if (puVar7[0x23] == 0x836) {
      for (bVar14 = 0; bVar14 < 4; bVar14 = bVar14 + 1) {
        uVar9 = (uint)bVar14;
        if ((*(byte *)(iVar16 + uVar9 + 0x5c) & 1) == 0) {
          iVar12 = uVar9 * 2;
          iVar11 = iVar16 + iVar12;
          *puVar7 = *(ushort *)(iVar11 + 0x44);
          puVar7[1] = *(ushort *)(iVar11 + 0x4c);
          puVar7[2] = *(ushort *)(iVar11 + 0x54);
          dVar17 = DOUBLE_803e4068;
          uStack_fc = (int)*(short *)(&DAT_803dc9e0 + iVar12) ^ 0x80000000;
          local_100 = 0x43300000;
          uStack_f4 = (int)*(short *)(iVar11 + 0x44) ^ 0x80000000;
          local_f8 = 0x43300000;
          iVar10 = (int)(dVar21 * (double)(float)((double)CONCAT44(0x43300000,uStack_fc) -
                                                 DOUBLE_803e4068) +
                        (double)(float)((double)CONCAT44(0x43300000,uStack_f4) - DOUBLE_803e4068));
          local_f0 = (longlong)iVar10;
          *(short *)(iVar11 + 0x44) = (short)iVar10;
          uStack_e4 = (int)*(short *)(&DAT_803dc9e8 + iVar12) ^ 0x80000000;
          local_e8 = 0x43300000;
          uStack_dc = (int)*(short *)(iVar11 + 0x4c) ^ 0x80000000;
          local_e0 = 0x43300000;
          iVar10 = (int)(dVar21 * (double)(float)((double)CONCAT44(0x43300000,uStack_e4) - dVar17) +
                        (double)(float)((double)CONCAT44(0x43300000,uStack_dc) - dVar17));
          local_d8 = (longlong)iVar10;
          *(short *)(iVar11 + 0x4c) = (short)iVar10;
          local_d0 = (double)CONCAT44(0x43300000,
                                      (int)*(short *)(&DAT_803dc9f0 + iVar12) ^ 0x80000000);
          uStack_c4 = (int)*(short *)(iVar11 + 0x54) ^ 0x80000000;
          local_c8 = 0x43300000;
          iVar10 = (int)(dVar21 * (double)(float)(local_d0 - dVar17) +
                        (double)(float)((double)CONCAT44(0x43300000,uStack_c4) - dVar17));
          local_c0 = (longlong)iVar10;
          *(short *)(iVar11 + 0x54) = (short)iVar10;
          iVar10 = iVar16 + uVar9 * 4;
          *(float *)(puVar7 + 4) =
               (float)((double)*(float *)(iVar10 + 0x24) * dVar22) *
               (*(float *)(iVar16 + 4) / *(float *)(iVar16 + 0x10));
          local_b8 = 0x43300000;
          iVar10 = (int)(*(float *)(iVar10 + 0x14) *
                        (float)((double)CONCAT44(0x43300000,uVar15) - DOUBLE_803e4078));
          local_b0 = (double)(longlong)iVar10;
          *(char *)((int)puVar7 + 0x37) = (char)iVar10;
          *(ushort *)(iVar8 + 0x18) = *(ushort *)(iVar8 + 0x18) & 0xfff7;
          uStack_b4 = uVar15;
          FUN_8003b818((int)puVar7);
        }
      }
    }
    else {
      for (bVar14 = 0; bVar14 < 4; bVar14 = bVar14 + 1) {
        uVar6 = (uint)bVar14;
        if ((*(byte *)(iVar16 + uVar6 + 0x5c) & 1) == 0) {
          iVar12 = uVar6 * 2 + 0x44;
          *puVar7 = *(ushort *)(iVar16 + iVar12);
          local_b0 = (double)CONCAT44(0x43300000,
                                      (int)*(short *)(&DAT_803dc9d8 + uVar6 * 2) ^ 0x80000000);
          uStack_b4 = (int)*(short *)(iVar16 + iVar12) ^ 0x80000000;
          local_b8 = 0x43300000;
          iVar10 = (int)(dVar21 * (double)(float)(local_b0 - DOUBLE_803e4068) +
                        (double)(float)((double)CONCAT44(0x43300000,uStack_b4) - DOUBLE_803e4068));
          local_c0 = (longlong)iVar10;
          *(short *)(iVar16 + iVar12) = (short)iVar10;
          iVar10 = iVar16 + uVar6 * 4;
          *(float *)(puVar7 + 4) = (float)((double)*(float *)(iVar10 + 0x24) * dVar22);
          local_c8 = 0x43300000;
          iVar10 = (int)(*(float *)(iVar10 + 0x14) *
                        (float)((double)CONCAT44(0x43300000,uVar15) - DOUBLE_803e4078));
          local_d0 = (double)(longlong)iVar10;
          *(char *)((int)puVar7 + 0x37) = (char)iVar10;
          *(ushort *)(iVar8 + 0x18) = *(ushort *)(iVar8 + 0x18) & 0xfff7;
          uStack_c4 = uVar15;
          FUN_8003b818((int)puVar7);
          if ((uVar9 & 0xff) == 0) {
            dVar17 = (double)lbl_803E4070;
            dVar18 = (double)lbl_803E4074;
            dVar19 = (double)lbl_803E4044;
            dVar20 = (double)lbl_803E405C;
            for (bVar13 = 0; bVar13 < 2; bVar13 = bVar13 + 1) {
              local_10c = (float)(dVar17 * (double)*(float *)(puVar7 + 4));
              local_108 = (float)(dVar18 * (double)*(float *)(puVar7 + 4));
              local_104 = (float)dVar19;
              *puVar7 = *puVar7 + 0x7fff;
              FUN_80017748(puVar7,&local_10c);
              local_10c = local_10c + *(float *)(puVar7 + 6);
              local_108 = local_108 + *(float *)(puVar7 + 8);
              local_104 = local_104 + *(float *)(puVar7 + 10);
              local_110 = (float)dVar20;
              (**(code **)(*DAT_803dd708 + 8))(puVar7,0x7ec,auStack_118,0x200001,0xffffffff,0);
            }
          }
        }
      }
    }
    *(float *)(puVar7 + 4) = (float)dVar22;
    *(byte *)(puVar7 + 0x1b) = bVar1;
    *puVar7 = uVar3;
    puVar7[1] = uVar4;
    puVar7[2] = uVar5;
  }
  FUN_80286860();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80170df4
 * EN v1.0 Address: 0x80170DF4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017141C
 * EN v1.1 Size: 808b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80170df4(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80170df8
 * EN v1.0 Address: 0x80170DF8
 * EN v1.0 Size: 80b
 * EN v1.1 Address: 0x80171744
 * EN v1.1 Size: 136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80170df8(int param_1)
{
  int iVar1;
  
  iVar1 = FUN_80017a54(param_1);
  FUN_80017958(iVar1,FUN_80017954);
  if (*(short *)(param_1 + 0x46) == 0x836) {
    FUN_80170048();
  }
  else {
    FUN_80170048();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80170e48
 * EN v1.0 Address: 0x80170E48
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801717CC
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80170e48(int param_1)
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
 * Function: FUN_80170e70
 * EN v1.0 Address: 0x80170E70
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x801718B8
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80170e70(int param_1)
{
  (**(code **)(*DAT_803dd6fc + 0x18))();
  FUN_80006b0c(DAT_803de730);
  FUN_80006b0c(DAT_803de734);
  DAT_803de730 = (undefined4*)0x0;
  DAT_803de734 = (undefined4*)0x0;
  ObjGroup_RemoveObject(param_1,0x3e);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80170ed8
 * EN v1.0 Address: 0x80170ED8
 * EN v1.0 Size: 136b
 * EN v1.1 Address: 0x8017191C
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80170ed8(void)
{
  float fVar1;
  int iVar2;
  char in_r8;
  
  iVar2 = FUN_80286840();
  if ((*(char *)((int)*(float **)(iVar2 + 0xb8) + 9) == '\0') && (in_r8 != '\0')) {
    fVar1 = **(float **)(iVar2 + 0xb8);
    if (fVar1 != lbl_803E4098) {
      FUN_8003b540(200,0,0,(char)(int)fVar1);
    }
    FUN_8003b818(iVar2);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80170f60
 * EN v1.0 Address: 0x80170F60
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801719C8
 * EN v1.1 Size: 948b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80170f60(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80170f64
 * EN v1.0 Address: 0x80170F64
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80171D7C
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80170f64(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: checkpoint4_render
 * EN v1.0 Address: 0x80170F68
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x80171EA4
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void checkpoint4_render(int param_1)
{
  FUN_8003b818(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: checkpoint4_init
 * EN v1.0 Address: 0x80170F88
 * EN v1.0 Size: 308b
 * EN v1.1 Address: 0x80171ED0
 * EN v1.1 Size: 392b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void checkpoint4_init(ushort *param_1,int param_2)
{
  float fVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  ushort local_78;
  ushort local_76;
  ushort local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  float afStack_60 [16];
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  iVar4 = *(int *)(param_1 + 0x5c);
  uStack_1c = *(byte *)(param_2 + 0x2a) ^ 0x80000000;
  local_20 = 0x43300000;
  local_18 = 0x43300000;
  fVar1 = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e40d0);
  if ((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e40d0) < lbl_803E40BC) {
    fVar1 = lbl_803E40BC;
  }
  *(float *)(param_1 + 4) = fVar1 * lbl_803E40C0;
  *param_1 = (ushort)((int)(short)(ushort)*(byte *)(param_2 + 0x29) << 8);
  local_78 = *param_1;
  local_76 = param_1[1];
  local_74 = param_1[2];
  local_70 = lbl_803E40B8;
  local_6c = lbl_803E40C4;
  local_68 = lbl_803E40C4;
  local_64 = lbl_803E40C4;
  uStack_14 = uStack_1c;
  FUN_80017754(afStack_60,&local_78);
  FUN_80017778((double)lbl_803E40C4,(double)lbl_803E40C4,(double)lbl_803E40B8,afStack_60,
               (float *)(iVar4 + 0x10),(float *)(iVar4 + 0x14),(float *)(iVar4 + 0x18));
  *(float *)(iVar4 + 0x1c) =
       -(*(float *)(param_1 + 10) * *(float *)(iVar4 + 0x18) +
        *(float *)(param_1 + 6) * *(float *)(iVar4 + 0x10) +
        *(float *)(param_1 + 8) * *(float *)(iVar4 + 0x14));
  *(float *)(iVar4 + 0x20) = lbl_803E40C8 * *(float *)(param_1 + 4);
  iVar3 = 0;
  do {
    uVar2 = FUN_80017760(0,0xf0);
    *(short *)(iVar4 + 0x34) = (short)uVar2;
    iVar4 = iVar4 + 2;
    iVar3 = iVar3 + 1;
  } while (iVar3 < 4);
  *(int *)(param_1 + 0x7a) = (int)*(char *)(param_2 + 0x28);
  param_1[0x58] = param_1[0x58] | 0xa000;
  return;
}

/*
 * --INFO--
 *
 * Function: sideload_update
 * EN v1.0 Address: 0x801710BC
 * EN v1.0 Size: 352b
 * EN v1.1 Address: 0x80172058
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void sideload_update(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                    undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                    int param_9)
{
  uint uVar1;
  int iVar2;
  undefined2 *puVar3;
  short *psVar4;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar5;
  
  iVar5 = *(int *)(param_9 + 0x4c);
  uVar1 = FUN_80017ae8();
  if (((((uVar1 & 0xff) != 0) && (iVar2 = FUN_80017a98(), iVar2 != 0)) &&
      (iVar2 = FUN_80017a90(), iVar2 == 0)) &&
     (uVar1 = FUN_80017690((int)*(short *)(iVar5 + 0x18)), uVar1 != 0)) {
    puVar3 = FUN_80017aa4(0x18,0x24);
    *(undefined *)(puVar3 + 2) = 2;
    *(undefined *)((int)puVar3 + 5) = 4;
    *(undefined *)((int)puVar3 + 7) = 0xff;
    *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(param_9 + 0xc);
    *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(param_9 + 0x10);
    *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(param_9 + 0x14);
    psVar4 = (short *)FUN_80017ae4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                   puVar3,5,0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    *psVar4 = (ushort)*(byte *)(iVar5 + 0x1a) << 8;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017121c
 * EN v1.0 Address: 0x8017121C
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8017212C
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017121c(int param_1)
{
  ObjGroup_RemoveObject(param_1,0x40);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80171240
 * EN v1.0 Address: 0x80171240
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x80172150
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80171240(int param_1,int param_2)
{
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0xe000;
  ObjGroup_AddObject(param_1,0x40);
  if (*(int *)(param_1 + 0x54) != 0) {
    FUN_80035b84(param_1,(short)((int)(uint)*(ushort *)(param_2 + 0x18) >> 3));
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801712a8
 * EN v1.0 Address: 0x801712A8
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x801721C0
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801712a8(double param_1,double param_2,double param_3,int param_4)
{
  int iVar1;
  uint uVar2;
  
  iVar1 = *(int *)(param_4 + 0xb8);
  *(float *)(param_4 + 0xc) = (float)param_1;
  *(float *)(iVar1 + 0x24) = (float)param_1;
  *(float *)(param_4 + 0x10) = (float)param_2;
  *(float *)(iVar1 + 0x28) = (float)param_2;
  *(float *)(param_4 + 0x14) = (float)param_3;
  *(float *)(iVar1 + 0x2c) = (float)param_3;
  uVar2 = FUN_80017690((int)*(short *)(iVar1 + 0x10));
  if (uVar2 == 0) {
    FUN_800e8630(param_4);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80171310
 * EN v1.0 Address: 0x80171310
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x80172254
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80171310(int param_1)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (*(int *)(iVar2 + 0x18) == -2) {
    uVar1 = FUN_80038b0c();
    *(uint *)(iVar2 + 0x18) = uVar1 & 0xffff;
  }
  return *(undefined4 *)(iVar2 + 0x18);
}

/*
 * --INFO--
 *
 * Function: FUN_80171354
 * EN v1.0 Address: 0x80171354
 * EN v1.0 Size: 88b
 * EN v1.1 Address: 0x801722A4
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80171354(int param_1,int param_2)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *(char *)(iVar2 + 0xf) = (char)param_2;
  if (param_2 == 0) {
    uVar1 = FUN_80017690((int)*(short *)(iVar2 + 0x10));
    if (uVar1 == 0) {
      ObjHits_EnableObject(param_1);
    }
  }
  else {
    ObjHits_DisableObject(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801713ac
 * EN v1.0 Address: 0x801713AC
 * EN v1.0 Size: 956b
 * EN v1.1 Address: 0x80172308
 * EN v1.1 Size: 744b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801713ac(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  short sVar1;
  char cVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined8 uVar7;
  
  iVar6 = *(int *)(param_9 + 0xb8);
  iVar5 = *(int *)(param_9 + 0x4c);
  iVar4 = *(int *)(*(int *)(param_9 + 0x50) + 0x18);
  FUN_80017a98();
  FUN_80017a90();
  FUN_80017a98();
  FUN_80017a90();
  uVar7 = ObjHits_DisableObject(param_9);
  if ((*(ushort *)(param_9 + 6) & 0x2000) != 0) {
    *(float *)(iVar6 + 8) = lbl_803E40E8;
    if (*(int *)(param_9 + 100) != 0) {
      *(undefined4 *)(*(int *)(param_9 + 100) + 0x30) = 0x1000;
    }
  }
  if ((int)*(short *)(iVar6 + 0x10) != 0xffffffff) {
    FUN_80017698((int)*(short *)(iVar6 + 0x10),1);
    uVar7 = FUN_800e842c(param_9);
  }
  uVar3 = (uint)*(short *)(iVar5 + 0x1e);
  if (uVar3 != 0xffffffff) {
    uVar7 = FUN_80017698(uVar3,1);
  }
  uVar3 = (uint)*(short *)(iVar5 + 0x2c);
  if (0 < (int)uVar3) {
    FUN_80017688(uVar3);
  }
  sVar1 = *(short *)(iVar4 + 2);
  if (sVar1 == 4) {
    sVar1 = *(short *)(param_9 + 0x46);
    if (sVar1 == 0x3cd) {
      iVar4 = FUN_80017a98();
      FUN_80294d60(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4,2);
      uVar3 = FUN_80017a98();
      FUN_80006824(uVar3,0x49);
      FUN_80081118((double)lbl_803E40EC,param_9,1,0x28);
    }
    else if ((sVar1 < 0x3cd) && (sVar1 == 0xb)) {
      uVar3 = FUN_80017a98();
      uVar7 = FUN_80006824(uVar3,0x49);
      iVar4 = FUN_80017a98();
      FUN_80294d60(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4,4);
      FUN_80081118((double)lbl_803E40EC,param_9,3,0x28);
    }
    else {
      uVar3 = FUN_80017a98();
      FUN_80006824(uVar3,0x58);
      FUN_80081118((double)lbl_803E40EC,param_9,0xff,0x28);
    }
  }
  else if ((sVar1 < 4) && (sVar1 == 1)) {
    sVar1 = *(short *)(param_9 + 0x46);
    if (sVar1 == 0x319) {
      FUN_80006824(param_9,0x16a);
      FUN_80017698(0x3e9,1);
      *(undefined2 *)(iVar6 + 0x3c) = 0x4b0;
      FUN_80081118((double)lbl_803E40EC,param_9,0xff,0x28);
    }
    else {
      if (sVar1 < 0x319) {
        if (sVar1 == 0x5a) {
          FUN_80006824(param_9,0x49);
          FUN_80081118((double)lbl_803E40EC,param_9,2,0x28);
          goto LAB_801725bc;
        }
        if ((sVar1 < 0x5a) && (sVar1 == 0x22)) {
          FUN_80006824(param_9,0x49);
          FUN_80081118((double)lbl_803E40EC,param_9,0xff,0x28);
          goto LAB_801725bc;
        }
      }
      else if (sVar1 == 0x6a6) {
        uVar3 = FUN_80017690(0x86a);
        cVar2 = (char)uVar3;
        if (cVar2 < '\a') {
          cVar2 = cVar2 + '\x01';
        }
        FUN_80017698(0x86a,(int)cVar2);
        FUN_80081118((double)lbl_803E40EC,param_9,6,0x28);
        FUN_80006824(param_9,0x49);
        goto LAB_801725bc;
      }
      FUN_80006824(param_9,0x58);
      FUN_80081118((double)lbl_803E40EC,param_9,0xff,0x28);
    }
  }
  else {
    FUN_80006824(param_9,0x58);
    FUN_80081118((double)lbl_803E40EC,param_9,0xff,0x28);
  }
LAB_801725bc:
  *(undefined4 *)(param_9 + 8) = *(undefined4 *)(*(int *)(param_9 + 0x50) + 4);
  *(undefined4 *)(param_9 + 0xf4) = 1;
  return;
}

/* Trivial 4b 0-arg blr leaves. */
void mikabomb_release(void) {}
void mikabomb_initialise(void) {}
void mikabombshadow_free(void) {}
void mikabombshadow_hitDetect(void) {}
void mikabombshadow_release(void) {}
void mikabombshadow_initialise(void) {}
void fn_8016B8FC(void) {}
void fn_8016B900(void) {}
void fn_8016B994(void) {}
void fn_8016B998(void) {}
void gcbaddieshield_free(void) {}
void gcbaddieshield_hitDetect(void) {}
void gcbaddieshield_release(void) {}
void gcbaddieshield_initialise(void) {}
void baddieinterestp_free(void) {}
void baddieinterestp_hitDetect(void) {}
void baddieinterestp_init(void) {}
void baddieinterestp_release(void) {}
void baddieinterestp_initialise(void) {}
void staff_func0F(void) {}
void staff_func0E(void) {}
void staff_func0B(void) {}
void staff_setScale(void) {}
void staff_render(void) {}
void staff_hitDetect(void) {}
void fireball_release(void) {}
void fireball_initialise(void) {}
void flamethrowerspe_modelMtxFn(void) {}
void flamethrowerspe_free(void) {}
void flamethrowerspe_hitDetect(void) {}
void flamethrowerspe_release(void) {}
void flamethrowerspe_initialise(void) {}
void shield_hitDetect(void) {}
void shield_release(void) {}
void shield_initialise(void) {}
void fn_80171308(void) {}
void fn_8017131C(void) {}
void fn_80171518(void) {}
void fn_801719D8(void) {}
void fn_801719DC(void) {}
void fn_801719E0(void) {}
void fn_801719F4(void) {}
void fn_80171A1C(void) {}
void fn_80171A20(void) {}
void fn_80171BA4(void) {}
void fn_80171BA8(void) {}
void fn_80171D10(void) {}

/* 8b "li r3, N; blr" returners. */
int mikabombshadow_getExtraSize(void) { return 0x4; }
int mikabombshadow_func08(void) { return 0x0; }
int fn_8016B898(void) { return 0x8; }
int fn_8016B8A0(void) { return 0x0; }
int gcbaddieshield_getExtraSize(void) { return 0x8; }
int gcbaddieshield_func08(void) { return 0x0; }
int baddieinterestp_getExtraSize(void) { return 0x0; }
int baddieinterestp_func08(void) { return 0x0; }
int animatedobj_getExtraSize(void) { return 0x140; }
int dim2roofrub_getExtraSize(void) { return 0x140; }
int depthoffieldpoint_getExtraSize(void) { return 0x3; }
int staff_getExtraSize(void) { return 0xc0; }
int staff_func08(void) { return 0x9; }
int fireball_getExtraSize(void) { return 0x74; }
int fireball_func08(void) { return 0x0; }
int flamethrowerspe_getExtraSize(void) { return 0x14; }
int flamethrowerspe_func08(void) { return 0x0; }
int shield_getExtraSize(void) { return 0x60; }
int shield_func08(void) { return 0x0; }
int fn_80171300(void) { return 0x0; }
int fn_8017130C(void) { return 0x0; }
int fn_80171314(void) { return 0x0; }
int fn_801713FC(void) { return 0xc; }
int fn_80171404(void) { return 0x2; }
int fn_801719E4(void) { return 0x40; }
int fn_801719EC(void) { return 0x10; }
int fn_80171C78(void) { return 0x1; }

/* Pattern wrappers. */
s16 staff_func13(int *obj) { return *(s16*)((char*)((int**)obj)[0xb8/4] + 0x88); }
u8 fn_8016F16C(int *obj) { return *(u8*)((char*)((int**)obj)[0xb8/4] + 0x71); }
u8 fn_80171D8C(int *obj) { return *(u8*)((char*)((int**)obj)[0xb8/4] + 0x1e); }

/* 16b chained patterns. */
s32 staff_func16(int *obj) { return *(s8*)((char*)((int**)obj)[0xb8/4] + 0xb9); }

/* render-with-fn_8003B8F4 pattern. */
extern f32 lbl_803E31E8;
extern void fn_8003B8F4(f32);
extern f32 lbl_803E3220;
extern f32 lbl_803E33F0;
#pragma peephole off
void fn_8016B8CC(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) fn_8003B8F4(lbl_803E31E8); }
void baddieinterestp_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) fn_8003B8F4(lbl_803E3220); }
void fn_80171320(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) fn_8003B8F4(lbl_803E33F0); }
#pragma peephole reset

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E3388;
extern f32 lbl_803E3420;
#pragma scheduling off
#pragma peephole off
void flamethrowerspe_render(void) { fn_8003B8F4(lbl_803E3388); }
void fn_801719F8(void) { fn_8003B8F4(lbl_803E3420); }
#pragma peephole reset
#pragma scheduling reset

/* ObjGroup_RemoveObject(x, N) wrappers. */
#pragma scheduling off
#pragma peephole off
void fn_8016B8A8(int x) { ObjGroup_RemoveObject(x, 0x7); }
void fn_80171C80(int x) { ObjGroup_RemoveObject(x, 0x40); }
#pragma peephole reset
#pragma scheduling reset

/* misc 8b leaves */
int collectible_setScale(int *obj) { return *(int*)((char*)obj + 0xf4); }

/* misc 16b 4-insn patterns. */
#pragma scheduling off
#pragma peephole off
void fn_8016E81C(int *obj) { s32 v = 0x0; *(s32*)((char*)((int**)obj)[0xb8/4] + 0x48) = v; }
void flamethrowerspe_func0B(int *obj) { s32 v = 0x1; *(s32*)((char*)((int**)obj)[0xb8/4] + 0x10) = v; }
#pragma peephole reset
#pragma scheduling reset

extern void fn_8016CEE8(int *obj, int x);
#pragma scheduling off
#pragma peephole off
void fn_8016EB50(int *obj) { fn_8016CEE8(obj, *(int*)((char*)obj + 0xc4)); }
#pragma peephole reset
#pragma scheduling reset
