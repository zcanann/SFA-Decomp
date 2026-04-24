// Function: FUN_80238e34
// Entry: 80238e34
// Size: 276 bytes

void FUN_80238e34(undefined2 *param_1,int param_2)

{
  int iVar1;
  undefined4 *puVar2;
  
  puVar2 = *(undefined4 **)(param_1 + 0x5c);
  *puVar2 = 0;
  *(char *)(param_2 + 0x18) =
       *(char *)(param_2 + 0x18) + (char)((uint)(int)*(char *)(param_2 + 0x18) / 3) * -3;
  puVar2[1] = (&PTR_DAT_8032bef8)[*(char *)(param_2 + 0x18)];
  *(undefined *)(puVar2 + 2) = (&DAT_803dc42c)[*(char *)(param_2 + 0x18)];
  if ((undefined *)puVar2[1] == &DAT_803dc428) {
    FUN_80035e30(param_1,8);
  }
  if (*(char *)(param_2 + 0x19) == '\x02') {
    *param_1 = *(undefined2 *)(param_2 + 0x1c);
  }
  else {
    param_1[3] = param_1[3] | 0x4000;
  }
  iVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1e));
  if (iVar1 != 0) {
    *(byte *)((int)puVar2 + 9) = *(byte *)((int)puVar2 + 9) & 0x7f | 0x80;
    FUN_80035f00(param_1);
  }
  *(code **)(param_1 + 0x5e) = FUN_80238ab0;
  return;
}

