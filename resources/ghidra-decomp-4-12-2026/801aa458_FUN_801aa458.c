// Function: FUN_801aa458
// Entry: 801aa458
// Size: 224 bytes

/* WARNING: Removing unreachable block (ram,0x801aa4b4) */

void FUN_801aa458(int param_1)

{
  uint uVar1;
  char *pcVar2;
  float local_18 [4];
  
  local_18[0] = FLOAT_803e52a8;
  pcVar2 = *(char **)(param_1 + 0xb8);
  uVar1 = FUN_80020078(0x1c0);
  if (uVar1 != 0) {
    FUN_80036f50(5,param_1,local_18);
    if (*pcVar2 == '\x01') {
      if (FLOAT_803e52ac <= local_18[0]) {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x3df,0,0,0xffffffff,0);
      }
      else {
        *pcVar2 = '\0';
      }
    }
    else if ((*pcVar2 == '\0') && (FLOAT_803e52ac <= local_18[0])) {
      *pcVar2 = '\x01';
    }
  }
  return;
}

