// Function: FUN_801c728c
// Entry: 801c728c
// Size: 300 bytes

void FUN_801c728c(undefined2 *param_1,int param_2)

{
  uint uVar1;
  int *piVar2;
  int *piVar3;
  
  piVar3 = *(int **)(param_1 + 0x5c);
  DAT_803de840 = 0;
  DAT_803de844 = (undefined2 *)0x0;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(undefined *)((int)piVar3 + 0x2f) = 0;
  *(undefined *)(piVar3 + 0xc) = 0;
  piVar3[1] = (int)FLOAT_803e5c64;
  *(undefined2 *)(piVar3 + 8) = 0;
  *(undefined2 *)((int)piVar3 + 0x22) = 0;
  *(undefined2 *)(piVar3 + 9) = 0;
  *(undefined2 *)((int)piVar3 + 0x26) = 0xffff;
  *(undefined *)((int)piVar3 + 0x2e) = 0;
  piVar3[0xd] = 0;
  *(code **)(param_1 + 0x5e) = FUN_801c6298;
  FUN_80037a5c((int)param_1,4);
  FUN_800201ac(0xba5,1);
  FUN_800201ac(0x129,1);
  FUN_800201ac(0x143,0);
  *(undefined2 *)(piVar3 + 6) = 0xc;
  *(undefined2 *)(piVar3 + 7) = 0x1e;
  piVar3[2] = (int)FLOAT_803e5c68;
  *(undefined2 *)((int)piVar3 + 0x1a) = 0;
  *(undefined2 *)((int)piVar3 + 0x1e) = 0;
  uVar1 = FUN_80020078(0x58b);
  *(char *)((int)piVar3 + 0x32) = (char)uVar1;
  DAT_803de844 = param_1;
  FUN_800372f8((int)param_1,0xb);
  *(undefined4 *)(param_1 + 0x7a) = 1;
  if (*piVar3 == 0) {
    piVar2 = FUN_8001f58c(0,'\x01');
    *piVar3 = (int)piVar2;
  }
  FUN_800201ac(0xefa,1);
  return;
}

