// Function: FUN_80211a10
// Entry: 80211a10
// Size: 524 bytes

void FUN_80211a10(undefined2 *param_1,int param_2)

{
  char cVar1;
  undefined4 *puVar2;
  
  puVar2 = *(undefined4 **)(param_1 + 0x5c);
  if (param_1[0x23] == 0x789) {
    *(undefined *)(param_2 + 0x19) = 2;
  }
  *param_1 = 0;
  FUN_80035f00(param_1);
  *(undefined *)(puVar2 + 0xb) = 0;
  FUN_8008016c(puVar2 + 5);
  FUN_8008016c(puVar2 + 7);
  FUN_8008016c(puVar2 + 8);
  FUN_80080178(puVar2 + 8,0x14);
  FUN_8008016c(puVar2 + 6);
  FUN_8008016c(puVar2 + 9);
  FUN_80080178(puVar2 + 9,5);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  FUN_8008016c(puVar2 + 10);
  FUN_80080178(puVar2 + 10,(int)(short)DAT_803dc230);
  *(undefined *)((int)puVar2 + 0x2e) = 0;
  puVar2[2] = FLOAT_803e6774;
  *(undefined *)(puVar2 + 0xc) = 0;
  cVar1 = *(char *)(param_2 + 0x19);
  if (cVar1 == '\x01') {
    FUN_80080178(puVar2 + 6,800);
    FUN_80080178(puVar2 + 7,800);
    *param_1 = *(undefined2 *)(param_2 + 0x1a);
    *(undefined *)(puVar2 + 0xb) = 0xff;
    *(float *)(param_1 + 4) = *(float *)(param_1 + 4) * FLOAT_803e6798;
  }
  else if (cVar1 < '\x01') {
    if (-1 < cVar1) {
      FUN_80080178(puVar2 + 7,(int)*(short *)(param_2 + 0x1a));
      *(undefined *)(puVar2 + 0xb) = 2;
      FUN_8002b884(param_1,1);
      *(float *)(param_1 + 4) = *(float *)(param_1 + 4) * FLOAT_803e6798;
    }
  }
  else if (cVar1 < '\x03') {
    FUN_8008016c(puVar2 + 10);
    *(undefined *)(puVar2 + 0xb) = 3;
    FUN_80035f20(param_1);
    puVar2[2] = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000) -
                       DOUBLE_803e6790);
    FUN_8008016c(puVar2 + 8);
  }
  puVar2[3] = (FLOAT_803e679c * *(float *)(param_1 + 4)) /
              (float)((double)CONCAT44(0x43300000,DAT_803dc230 ^ 0x80000000) - DOUBLE_803e6790);
  *puVar2 = 0;
  puVar2[1] = 0;
  return;
}

