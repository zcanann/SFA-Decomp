// Function: FUN_8003842c
// Entry: 8003842c
// Size: 444 bytes

void FUN_8003842c(undefined4 param_1,undefined4 param_2,float *param_3,undefined4 *param_4,
                 float *param_5,int param_6)

{
  int *piVar1;
  undefined *puVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined8 uVar6;
  undefined2 local_118;
  undefined2 local_116;
  undefined2 local_114;
  float local_10c;
  undefined4 local_108;
  float local_104;
  undefined auStack256 [64];
  undefined auStack192 [12];
  float local_b4;
  undefined4 local_a4;
  float local_94;
  undefined auStack144 [48];
  undefined auStack96 [96];
  
  uVar6 = FUN_802860d4();
  iVar3 = (int)((ulonglong)uVar6 >> 0x20);
  iVar5 = (int)uVar6;
  if ((iVar5 < 0) || ((int)(uint)*(byte *)(*(int *)(iVar3 + 0x50) + 0x58) <= iVar5)) {
    *param_3 = *(float *)(iVar3 + 0xc);
    *param_4 = *(undefined4 *)(iVar3 + 0x10);
    *param_5 = *(float *)(iVar3 + 0x14);
  }
  else {
    piVar1 = (int *)FUN_8002b588();
    iVar5 = iVar5 * 0x18;
    iVar4 = (int)*(char *)(*(int *)(*(int *)(iVar3 + 0x50) + 0x2c) + iVar5 +
                           (int)*(char *)(iVar3 + 0xad) + 0x12);
    if ((iVar4 < -1) || ((int)(uint)*(byte *)(*piVar1 + 0xf3) <= iVar4)) {
      *param_3 = *(float *)(iVar3 + 0xc);
      *param_4 = *(undefined4 *)(iVar3 + 0x10);
      *param_5 = *(float *)(iVar3 + 0x14);
    }
    else {
      if (iVar4 == -1) {
        FUN_8002b47c(iVar3,auStack96,0);
        puVar2 = auStack96;
      }
      else {
        puVar2 = (undefined *)FUN_8002856c();
      }
      if (param_6 == 0) {
        iVar3 = *(int *)(*(int *)(iVar3 + 0x50) + 0x2c);
        local_10c = *(float *)(iVar3 + iVar5);
        iVar3 = iVar3 + iVar5;
        local_108 = *(undefined4 *)(iVar3 + 4);
        local_104 = *(float *)(iVar3 + 8);
        local_118 = *(undefined2 *)(iVar3 + 0xc);
        local_116 = *(undefined2 *)(iVar3 + 0xe);
        local_114 = *(undefined2 *)(iVar3 + 0x10);
      }
      else {
        local_10c = *param_3;
        local_108 = *param_4;
        local_104 = *param_5;
        local_118 = 0;
        local_116 = 0;
        local_114 = 0;
      }
      FUN_80021ba0(auStack256,&local_118);
      FUN_80021608(auStack256,auStack144);
      FUN_80246eb4(puVar2,auStack144,auStack192);
      *param_3 = local_b4 + FLOAT_803dcdd8;
      *param_4 = local_a4;
      *param_5 = local_94 + FLOAT_803dcddc;
    }
  }
  FUN_80286120();
  return;
}

