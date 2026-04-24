// Function: FUN_801a9ea4
// Entry: 801a9ea4
// Size: 224 bytes

/* WARNING: Removing unreachable block (ram,0x801a9f00) */

void FUN_801a9ea4(int param_1)

{
  int iVar1;
  char *pcVar2;
  float local_18 [4];
  
  local_18[0] = FLOAT_803e4610;
  pcVar2 = *(char **)(param_1 + 0xb8);
  iVar1 = FUN_8001ffb4(0x1c0);
  if (iVar1 != 0) {
    FUN_80036e58(5,param_1,local_18);
    if (*pcVar2 == '\x01') {
      if (FLOAT_803e4614 <= local_18[0]) {
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x3df,0,0,0xffffffff,0);
      }
      else {
        *pcVar2 = '\0';
      }
    }
    else if ((*pcVar2 == '\0') && (FLOAT_803e4614 <= local_18[0])) {
      *pcVar2 = '\x01';
    }
  }
  return;
}

