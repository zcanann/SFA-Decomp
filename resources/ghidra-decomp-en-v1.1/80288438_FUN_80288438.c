// Function: FUN_80288438
// Entry: 80288438
// Size: 136 bytes

void FUN_80288438(char *param_1)

{
  char cVar1;
  undefined4 uVar2;
  
  while (cVar1 = *param_1, param_1 = param_1 + 1, cVar1 != '\0') {
    uVar2 = FUN_8028adac();
    FUN_8028ada0(0);
    FUN_8007d858();
    FUN_8028ada0(uVar2);
  }
  return;
}

