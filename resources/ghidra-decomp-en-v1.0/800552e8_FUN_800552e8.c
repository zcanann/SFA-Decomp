// Function: FUN_800552e8
// Entry: 800552e8
// Size: 200 bytes

void FUN_800552e8(int param_1,char param_2)

{
  undefined4 *puVar1;
  
  puVar1 = DAT_803dce78;
  FUN_8001f71c(DAT_803dce78,0x1c,param_1 << 4,0x10);
  DAT_803879a0 = *puVar1;
  DAT_803879a4 = puVar1[1];
  DAT_803879a8 = puVar1[2];
  DAT_803879ac = *(undefined2 *)(puVar1 + 3);
  DAT_803879ae = *(undefined2 *)((int)puVar1 + 0xe);
  DAT_803dceba = (undefined2)param_1;
  DAT_803dcebd = 1;
  DAT_803dcebc = param_2;
  if (param_2 != '\0') {
    (**(code **)(*DAT_803dca4c + 8))(2,1);
  }
  FUN_8012fdb8(1);
  return;
}

