// Function: FUN_800163fc
// Entry: 800163fc
// Size: 236 bytes

void FUN_800163fc(undefined4 param_1,undefined4 param_2,undefined2 param_3,undefined2 param_4,
                 int *param_5,int *param_6,int *param_7,int *param_8)

{
  undefined2 uVar1;
  undefined2 uVar2;
  int iVar3;
  int extraout_r4;
  
  FUN_80286838();
  iVar3 = extraout_r4 * 0x20;
  uVar1 = *(undefined2 *)(&DAT_802c7b98 + iVar3);
  uVar2 = *(undefined2 *)(&DAT_802c7b9a + iVar3);
  DAT_803dd63c = 1;
  DAT_803dd630 = 0x7fffffff;
  DAT_803dd62c = 0;
  DAT_803dd638 = 0x7fffffff;
  DAT_803dd634 = 0;
  *(undefined2 *)(&DAT_802c7b98 + iVar3) = param_3;
  *(undefined2 *)(&DAT_802c7b9a + iVar3) = param_4;
  FUN_80015ebc();
  DAT_803dd63c = 0;
  if (param_7 != (int *)0x0) {
    *param_7 = DAT_803dd638 >> 2;
  }
  if (param_8 != (int *)0x0) {
    *param_8 = DAT_803dd634 >> 2;
  }
  if (param_5 != (int *)0x0) {
    *param_5 = DAT_803dd630 >> 2;
  }
  if (param_6 != (int *)0x0) {
    *param_6 = DAT_803dd62c >> 2;
  }
  *(undefined2 *)(&DAT_802c7b98 + iVar3) = uVar1;
  *(undefined2 *)(&DAT_802c7b9a + iVar3) = uVar2;
  FUN_80286884();
  return;
}

