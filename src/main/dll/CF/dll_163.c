#include "ghidra_import.h"
#include "main/dll/CF/dll_163.h"

extern uint FUN_80017730();
extern undefined4 FUN_80017748();
extern uint FUN_80017760();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 FUN_8013651c();
extern int FUN_80286834();
extern undefined4 FUN_80286880();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();

extern undefined4 DAT_803dca48;
extern undefined4* DAT_803dd72c;
extern f64 DOUBLE_803e4868;
extern f64 DOUBLE_803e4880;
extern f32 FLOAT_803e4854;
extern f32 FLOAT_803e485c;
extern f32 FLOAT_803e4870;
extern f32 FLOAT_803e4874;
extern f32 FLOAT_803e4878;
extern f32 FLOAT_803e4888;
extern f32 FLOAT_803e4894;

/*
 * --INFO--
 *
 * Function: FUN_80189f5c
 * EN v1.0 Address: 0x80189F5C
 * EN v1.0 Size: 976b
 * EN v1.1 Address: 0x8018A1C0
 * EN v1.1 Size: 732b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80189f5c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  undefined2 *puVar6;
  short *psVar7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined4 *puVar8;
  int iVar9;
  double dVar10;
  double dVar11;
  double in_f27;
  double dVar12;
  double in_f28;
  double dVar13;
  double in_f29;
  double dVar14;
  double in_f30;
  double dVar15;
  double in_f31;
  double dVar16;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  ushort local_98 [4];
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  undefined4 local_80;
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
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
  iVar1 = FUN_80286834();
  iVar9 = *(int *)(iVar1 + 0x4c);
  iVar2 = FUN_80017a98();
  iVar3 = FUN_80017a90();
  puVar8 = *(undefined4 **)(iVar1 + 0xb8);
  iVar4 = (**(code **)(*DAT_803dd72c + 0x68))(*(undefined4 *)(iVar9 + 0x14));
  if ((iVar4 != 0) && (uVar5 = FUN_80017ae8(), (uVar5 & 0xff) != 0)) {
    dVar11 = (double)FLOAT_803e4870;
    uStack_7c = (uint)*(byte *)(iVar9 + 0x20);
    local_80 = 0x43300000;
    dVar10 = (double)(**(code **)(*DAT_803dd72c + 100))
                               ((double)(float)(dVar11 * (double)(float)((double)CONCAT44(0x43300000
                                                                                          ,uStack_7c
                                                                                         ) -
                                                                        DOUBLE_803e4880)),
                                *(undefined4 *)(iVar9 + 0x14));
    if (iVar3 != 0) {
      dVar10 = (double)FUN_8013651c(iVar3);
    }
    dVar16 = (double)FLOAT_803e4874;
    dVar13 = (double)FLOAT_803e485c;
    dVar14 = (double)FLOAT_803e4854;
    dVar15 = (double)FLOAT_803e4878;
    dVar12 = DOUBLE_803e4868;
    for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(iVar9 + 0x1f); iVar3 = iVar3 + 1) {
      puVar6 = FUN_80017aa4(0x24,*(undefined2 *)(&DAT_803dca48 + (uint)*(byte *)(iVar9 + 0x1e) * 2))
      ;
      *(undefined4 *)(puVar6 + 4) = *puVar8;
      *(undefined4 *)(puVar6 + 6) = *(undefined4 *)(iVar1 + 0x10);
      *(undefined4 *)(puVar6 + 8) = puVar8[1];
      puVar6[0xd] = 400;
      psVar7 = (short *)FUN_80017ae4(dVar10,dVar11,param_3,param_4,param_5,param_6,param_7,param_8,
                                     puVar6,5,*(undefined *)(iVar1 + 0xac),0xffffffff,
                                     *(uint **)(iVar1 + 0x30),in_r8,in_r9,in_r10);
      *(float *)(psVar7 + 0x12) = *(float *)(iVar1 + 0xc) - *(float *)(iVar2 + 0xc);
      *(float *)(psVar7 + 0x16) = *(float *)(iVar1 + 0x14) - *(float *)(iVar2 + 0x14);
      dVar10 = (double)(*(float *)(psVar7 + 0x12) * *(float *)(psVar7 + 0x12) +
                       *(float *)(psVar7 + 0x16) * *(float *)(psVar7 + 0x16));
      if (dVar10 != dVar16) {
        dVar10 = FUN_80293900(dVar10);
        *(float *)(psVar7 + 0x12) = (float)((double)*(float *)(psVar7 + 0x12) / dVar10);
        *(float *)(psVar7 + 0x16) = (float)((double)*(float *)(psVar7 + 0x16) / dVar10);
      }
      uStack_7c = FUN_80017760(0,0x19);
      uStack_7c = uStack_7c ^ 0x80000000;
      local_80 = 0x43300000;
      *(float *)(psVar7 + 0x12) =
           *(float *)(psVar7 + 0x12) *
           -(float)(dVar13 * (double)(float)((double)CONCAT44(0x43300000,uStack_7c) - dVar12) -
                   dVar14);
      uStack_74 = FUN_80017760(0,0x19);
      uStack_74 = uStack_74 ^ 0x80000000;
      local_78 = 0x43300000;
      *(float *)(psVar7 + 0x16) =
           *(float *)(psVar7 + 0x16) *
           -(float)(dVar13 * (double)(float)((double)CONCAT44(0x43300000,uStack_74) - dVar12) -
                   dVar14);
      *(float *)(psVar7 + 0x14) = (float)dVar15;
      local_8c = (float)dVar16;
      local_88 = (float)dVar16;
      local_84 = (float)dVar16;
      local_90 = (float)dVar14;
      local_98[2] = 0;
      local_98[1] = 0;
      uVar5 = FUN_80017760(0xffffd8f0,10000);
      local_98[0] = (ushort)uVar5;
      FUN_80017748(local_98,(float *)(psVar7 + 0x12));
      dVar10 = (double)*(float *)(psVar7 + 0x12);
      dVar11 = -(double)*(float *)(psVar7 + 0x16);
      uVar5 = FUN_80017730();
      iVar4 = (int)*psVar7 - (uVar5 & 0xffff);
      if (0x8000 < iVar4) {
        iVar4 = iVar4 + -0xffff;
      }
      if (iVar4 < -0x8000) {
        iVar4 = iVar4 + 0xffff;
      }
      *psVar7 = (short)iVar4;
    }
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018a32c
 * EN v1.0 Address: 0x8018A32C
 * EN v1.0 Size: 28b
 * EN v1.1 Address: 0x8018A49C
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
byte FUN_8018a32c(int param_1)
{
  byte bVar1;
  
  bVar1 = *(byte *)(*(int *)(param_1 + 0x4c) + 0x1d);
  if (bVar1 < 3) {
    return bVar1;
  }
  return 2;
}

/*
 * --INFO--
 *
 * Function: FUN_8018a348
 * EN v1.0 Address: 0x8018A348
 * EN v1.0 Size: 516b
 * EN v1.1 Address: 0x8018A4B4
 * EN v1.1 Size: 676b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018a348(int param_1,float *param_2,float *param_3)
{
  byte bVar1;
  float *pfVar2;
  double dVar3;
  
  pfVar2 = *(float **)(param_1 + 0xb8);
  bVar1 = *(byte *)(*(int *)(param_1 + 0x4c) + 0x1c);
  if (bVar1 == 2) {
    dVar3 = (double)FUN_80293f90();
    *param_2 = -(float)((double)FLOAT_803e4888 * dVar3 - (double)*pfVar2);
    dVar3 = (double)FUN_80294964();
    *param_3 = -(float)((double)FLOAT_803e4888 * dVar3 - (double)pfVar2[1]);
  }
  else {
    if (bVar1 < 2) {
      if (bVar1 == 0) {
        dVar3 = (double)FUN_80293f90();
        *param_2 = (float)((double)FLOAT_803e4894 * dVar3 + (double)*(float *)(param_1 + 0xc));
        dVar3 = (double)FUN_80294964();
        *param_3 = (float)((double)FLOAT_803e4894 * dVar3 + (double)*(float *)(param_1 + 0x14));
        return;
      }
    }
    else if (bVar1 < 4) {
      dVar3 = (double)FUN_80293f90();
      *param_2 = (float)((double)FLOAT_803e4888 * dVar3 + (double)*pfVar2);
      dVar3 = (double)FUN_80294964();
      *param_3 = (float)((double)FLOAT_803e4888 * dVar3 + (double)pfVar2[1]);
      return;
    }
    dVar3 = (double)FUN_80293f90();
    *param_2 = (float)((double)FLOAT_803e4888 * dVar3 + (double)*(float *)(param_1 + 0xc));
    dVar3 = (double)FUN_80294964();
    *param_3 = (float)((double)FLOAT_803e4888 * dVar3 + (double)*(float *)(param_1 + 0x14));
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018a54c
 * EN v1.0 Address: 0x8018A54C
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8018A758
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8018a54c(int param_1)
{
  return *(undefined4 *)(*(int *)(param_1 + 0xb8) + 0x14);
}

/*
 * --INFO--
 *
 * Function: FUN_8018a558
 * EN v1.0 Address: 0x8018A558
 * EN v1.0 Size: 20b
 * EN v1.1 Address: 0x8018A764
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018a558(int param_1,undefined4 param_2)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(undefined4 *)(iVar1 + 0x14) = param_2;
  *(undefined *)(iVar1 + 0x1c) = 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018a56c
 * EN v1.0 Address: 0x8018A56C
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8018A778
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_8018a56c(int param_1)
{
  return *(undefined *)(*(int *)(param_1 + 0x4c) + 0x1c);
}

/*
 * --INFO--
 *
 * Function: FUN_8018a578
 * EN v1.0 Address: 0x8018A578
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8018A794
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018a578(int param_1)
{
  ObjGroup_RemoveObject(param_1,0x41);
  return;
}

/*
 * --INFO--
 *
 * Function: staffactivated_getExtraSize
 * EN v1.0 Address: 0x8018A22C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8018A438
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int staffactivated_getExtraSize(void)
{
  return 0x24;
}

/*
 * --INFO--
 *
 * Function: staffactivated_func08
 * EN v1.0 Address: 0x8018A234
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8018A440
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int staffactivated_func08(void)
{
  return 0x40;
}

/* Pattern wrappers. */
u32 fn_8018A200(int *obj) { return *(u32*)((char*)((int**)obj)[0xb8/4] + 0x14); }
u8 fn_8018A220(int *obj) { return *(u8*)((char*)((int**)obj)[0x4c/4] + 0x1c); }

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E3BBC;
extern void fn_8003B8F4(f32);
#pragma scheduling off
void staffactivated_render(void) { fn_8003B8F4(lbl_803E3BBC); }
#pragma scheduling reset

/* ObjGroup_RemoveObject(x, N) wrappers. */
#pragma scheduling off
int staffactivated_free(int x) { return ObjGroup_RemoveObject(x, 0x41); }
#pragma scheduling reset
