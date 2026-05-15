#include "ghidra_import.h"
#include "main/dll/DR/DRsimplehuman.h"

extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068cc();
extern undefined4 FUN_800068d0();
extern undefined4 FUN_800069a8();
extern double FUN_80017708();
extern int FUN_80017730();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_8001777c();
extern undefined4 FUN_80017958();
extern int FUN_80017a54();
extern undefined4 FUN_80017a88();
extern int FUN_80017a98();
extern undefined4 FUN_8002f6ac();
extern undefined FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjGroup_AddObject();
extern int FUN_800620e8();
extern undefined4 FUN_800810f4();
extern undefined4 FUN_80081118();
extern undefined4 FUN_801e8278();
extern undefined4 FUN_801e85b0();
extern undefined4 FUN_801f4f98();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();

extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dcd18;
extern undefined4 DAT_803dcd1c;
extern undefined4* DAT_803dd708;
extern undefined4 DAT_803e6708;
extern undefined4 DAT_803e670a;
extern f64 DOUBLE_803e6730;
extern f32 lbl_803DC074;
extern f32 lbl_803E670C;
extern f32 lbl_803E6710;
extern f32 lbl_803E6718;
extern f32 lbl_803E671C;
extern f32 lbl_803E6720;
extern f32 lbl_803E672C;
extern f32 lbl_803E6738;
extern f32 lbl_803E673C;
extern f32 lbl_803E6740;
extern f32 lbl_803E6744;
extern f32 lbl_803E6748;
extern f32 lbl_803E674C;
extern f32 lbl_803E6750;
extern f32 lbl_803E6754;

/*
 * --INFO--
 *
 * Function: FUN_801e9344
 * EN v1.0 Address: 0x801E9344
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801E93B4
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e9344(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801e9348
 * EN v1.0 Address: 0x801E9348
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x801E94EC
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e9348(void)
{
  FUN_800068cc();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e9368
 * EN v1.0 Address: 0x801E9368
 * EN v1.0 Size: 808b
 * EN v1.1 Address: 0x801E9518
 * EN v1.1 Size: 588b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e9368(int *param_1)
{
  int iVar1;
  int iVar2;
  float *pfVar3;
  double dVar4;
  float local_80;
  float local_7c [2];
  int local_74;
  int aiStack_70 [7];
  float afStack_54 [18];
  
  pfVar3 = (float *)param_1[0x2e];
  iVar2 = param_1[0x13];
  if (*pfVar3 < (float)param_1[4]) {
    param_1[10] = (int)-(lbl_803E670C * lbl_803DC074 - (float)param_1[10]);
  }
  FUN_80017a88((double)(lbl_803DC074 * (float)param_1[9] * pfVar3[1]),
               (double)((float)param_1[10] * lbl_803DC074),
               (double)(lbl_803DC074 * (float)param_1[0xb] * pfVar3[1]),(int)param_1);
  dVar4 = FUN_80293900((double)((float)param_1[9] * (float)param_1[9] +
                               (float)param_1[0xb] * (float)param_1[0xb]));
  FUN_8002f6ac(dVar4,(int)param_1,&local_80);
  FUN_8002fc3c((double)local_80,(double)lbl_803DC074);
  if ((float)param_1[4] < *pfVar3) {
    param_1[4] = (int)*pfVar3;
    param_1[10] = (int)lbl_803E6710;
  }
  iVar1 = FUN_800620e8(param_1 + 0x20,param_1 + 3,(float *)0x0,aiStack_70,param_1,8,0xffffffff,0xff,
                       10);
  if (iVar1 != 0) {
    FUN_8001777c(afStack_54,(float *)(param_1 + 9),local_7c);
    param_1[9] = (int)local_7c[0];
    param_1[0xb] = local_74;
    iVar1 = FUN_80017730();
    *(short *)param_1 = (short)iVar1;
  }
  iVar1 = FUN_80017a98();
  dVar4 = FUN_80017708((float *)(iVar1 + 0x18),(float *)(param_1 + 6));
  if (dVar4 < (double)lbl_803E6718) {
    FUN_80006824((uint)param_1,*(ushort *)(pfVar3 + 3));
    FUN_80081118((double)lbl_803E671C,param_1,(int)*(short *)((int)pfVar3 + 0xe),0x28);
    *(ushort *)(param_1 + 0x2c) = *(ushort *)(param_1 + 0x2c) | 0x8000;
    *(ushort *)((int)param_1 + 6) = *(ushort *)((int)param_1 + 6) | 0x4000;
    (**(code **)(**(int **)((int)pfVar3[2] + 0x68) + 0x50))
              (pfVar3[2],*(char *)(iVar2 + 0x19) != '\0',*(char *)(iVar2 + 0x19) == '\0');
  }
  if (((*(ushort *)(param_1 + 0x2c) & 0x800) != 0) && ((int)*(short *)(pfVar3 + 4) != 0)) {
    FUN_800810f4((double)lbl_803E671C,(double)lbl_803E6720,param_1,5,
                 (int)*(short *)(pfVar3 + 4) & 0xff,1,0x14,0,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e9690
 * EN v1.0 Address: 0x801E9690
 * EN v1.0 Size: 428b
 * EN v1.1 Address: 0x801E9764
 * EN v1.1 Size: 536b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e9690(short *param_1,int param_2)
{
  char cVar1;
  int iVar2;
  uint uVar3;
  float *pfVar4;
  double dVar5;
  undefined2 local_38;
  undefined local_36;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  pfVar4 = *(float **)(param_1 + 0x5c);
  local_38 = DAT_803e6708;
  local_36 = DAT_803e670a;
  param_1[0x58] = param_1[0x58] | 0x6000;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  uStack_2c = (int)*param_1 ^ 0x80000000;
  local_30 = 0x43300000;
  dVar5 = (double)FUN_80293f90();
  *(float *)(param_1 + 0x12) = (float)-dVar5;
  uStack_24 = (int)*param_1 ^ 0x80000000;
  local_28 = 0x43300000;
  dVar5 = (double)FUN_80294964();
  *(float *)(param_1 + 0x16) = (float)-dVar5;
  *(char *)((int)param_1 + 0xad) = '\x01' - *(char *)(param_2 + 0x19);
  uStack_1c = (int)*(short *)(param_2 + 0x1a) ^ 0x80000000;
  local_20 = 0x43300000;
  *pfVar4 = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e6730);
  uStack_14 = randomGetRange(0,100);
  uStack_14 = uStack_14 ^ 0x80000000;
  local_18 = 0x43300000;
  pfVar4[1] = lbl_803E672C +
              (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e6730) / lbl_803E6718;
  pfVar4[2] = *(float *)(param_2 + 0x14);
  *(undefined4 *)(param_2 + 0x14) = 0xffffffff;
  FUN_800068d0((uint)param_1,0x406);
  iVar2 = FUN_80017a54((int)param_1);
  cVar1 = *(char *)(param_2 + 0x19);
  if (cVar1 == '\x01') {
    *(undefined2 *)(pfVar4 + 3) = 0x42;
    *(undefined2 *)((int)pfVar4 + 0xe) = 1;
    *(undefined2 *)(pfVar4 + 4) = 0;
  }
  else if ((cVar1 < '\x01') && (-1 < cVar1)) {
    uVar3 = randomGetRange(0,2);
    *(undefined *)(*(int *)(iVar2 + 0x34) + 8) = *(undefined *)((int)&local_38 + uVar3);
    *(undefined2 *)(pfVar4 + 3) = 0x41;
    *(undefined2 *)((int)pfVar4 + 0xe) = 4;
    *(undefined2 *)(pfVar4 + 4) = 2;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e983c
 * EN v1.0 Address: 0x801E983C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801E997C
 * EN v1.1 Size: 760b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e983c(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,
                 undefined4 param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: spitembeam_init
 * EN v1.0 Address: 0x801E9900
 * EN v1.0 Size: 20b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
void spitembeam_init(int obj)
{
  *(ushort *)(obj + 0xb0) = (ushort)(*(ushort *)(obj + 0xb0) | 0x6000);
}
#pragma peephole reset


/* Trivial 4b 0-arg blr leaves. */
void spdrape_release(void) {}
void spdrape_initialise(void) {}
void spitembeam_free(void) {}
void spitembeam_render(void) {}
void spitembeam_hitDetect(void) {}
void spitembeam_release(void) {}
void spitembeam_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int spitembeam_getExtraSize(void) { return 0x0; }
int spitembeam_func08(void) { return 0x0; }
