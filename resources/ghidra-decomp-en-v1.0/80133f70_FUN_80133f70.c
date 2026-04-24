// Function: FUN_80133f70
// Entry: 80133f70
// Size: 208 bytes

void FUN_80133f70(undefined4 param_1)

{
  char cVar3;
  undefined4 uVar1;
  int iVar2;
  int local_28;
  int local_24;
  int local_20;
  float local_1c;
  undefined auStack24 [20];
  
  local_1c = FLOAT_803e22a0;
  local_20 = 0;
  local_24 = 0;
  local_28 = 0;
  cVar3 = FUN_80014054();
  if (cVar3 != '\0') {
    FUN_800140bc(param_1);
  }
  uVar1 = FUN_8002b9ec();
  iVar2 = FUN_80036e58(9,uVar1,&local_1c);
  if (iVar2 != 0) {
    (**(code **)(**(int **)(iVar2 + 0x68) + 0x54))(iVar2,&local_20,&local_24,&local_28);
  }
  local_24 = local_28 - (local_24 - local_20);
  if (local_24 < 0) {
    local_24 = 0;
  }
  FUN_8028f688(auStack24,&DAT_803dbbf0,local_24);
  return;
}

