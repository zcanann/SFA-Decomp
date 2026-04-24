// Function: FUN_8002ea8c
// Entry: 8002ea8c
// Size: 448 bytes

void FUN_8002ea8c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  short *psVar2;
  int *piVar3;
  undefined4 uVar4;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar5;
  
  DAT_803dd818 = FUN_80023d8c(0x640,0xe);
  DAT_803dd810 = FUN_80023d8c(0x60,0xe);
  uVar4 = 0;
  DAT_803dd840 = FUN_80023d8c(0x10,0xe);
  uVar5 = FUN_8001f82c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,&DAT_803dd820
                       ,0x3f,uVar4,in_r6,in_r7,in_r8,in_r9,in_r10);
  iVar1 = FUN_8004908c(0x3f);
  DAT_803dd81c = (iVar1 >> 1) + -1;
  for (psVar2 = (short *)(DAT_803dd820 + DAT_803dd81c * 2); *psVar2 == 0; psVar2 = psVar2 + -1) {
    DAT_803dd81c = DAT_803dd81c + -1;
  }
  uVar5 = FUN_8001f82c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,&DAT_803dd83c,
                       0x3d,uVar4,in_r6,in_r7,in_r8,in_r9,in_r10);
  DAT_803dd838 = 0;
  for (piVar3 = DAT_803dd83c; *piVar3 != -1; piVar3 = piVar3 + 1) {
    DAT_803dd838 = DAT_803dd838 + 1;
  }
  DAT_803dd838 = DAT_803dd838 + -1;
  DAT_803dd828 = FUN_80023d8c(DAT_803dd838 * 4,0xe);
  DAT_803dd824 = FUN_80023d8c(DAT_803dd838,0xe);
  for (iVar1 = 0; iVar1 < DAT_803dd838; iVar1 = iVar1 + 1) {
    *(undefined *)(DAT_803dd824 + iVar1) = 0;
  }
  uVar5 = FUN_8001f82c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,&DAT_803dd834,
                       0x16,iVar1,in_r6,in_r7,in_r8,in_r9,in_r10);
  FUN_8001f82c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,&DAT_803dd830,0x17,
               iVar1,in_r6,in_r7,in_r8,in_r9,in_r10);
  DAT_803dd82c = 0;
  for (piVar3 = DAT_803dd830; *piVar3 != -1; piVar3 = piVar3 + 1) {
    DAT_803dd82c = DAT_803dd82c + 1;
  }
  DAT_803dd808 = FUN_80023d8c(0x960,0xe);
  FUN_80036c04();
  DAT_803dd814 = 0;
  DAT_803dd80c = 0;
  DAT_803dd7f0 = 0;
  DAT_803dd804 = 0;
  FUN_80013b8c(-0x7fc22804,0x38);
  DAT_803dd844 = 0;
  FUN_80037544();
  FUN_80036ae8();
  return;
}

