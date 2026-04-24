// Function: FUN_802151ec
// Entry: 802151ec
// Size: 104 bytes

void FUN_802151ec(undefined4 param_1)

{
  float local_18;
  float local_14;
  float local_10 [4];
  
  if (*(int *)(DAT_803ddd54 + 0x178) != 0) {
    FUN_8003842c(param_1,5,&local_18,&local_14,local_10,0);
    FUN_8001dd88((double)local_18,(double)local_14,(double)local_10[0],
                 *(undefined4 *)(DAT_803ddd54 + 0x178));
    FUN_8001d6b0(*(undefined4 *)(DAT_803ddd54 + 0x178));
  }
  return;
}

