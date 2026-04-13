// Function: FUN_802272bc
// Entry: 802272bc
// Size: 172 bytes

void FUN_802272bc(int param_1)

{
  char cVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  FUN_8003709c(param_1,9);
  cVar1 = *(char *)(iVar2 + 0x10);
  if (cVar1 == '\x01') {
    FUN_800201ac(0x7ef,0);
    FUN_800201ac(0x7ed,0);
    FUN_800201ac(0xba6,0);
    FUN_800201ac(0xedd,0);
  }
  else if (cVar1 == '\x02') {
    FUN_800201ac(0x7f0,0);
    FUN_800201ac(0x7ee,0);
    FUN_800201ac(0xba6,0);
    FUN_800201ac(0xedc,0);
  }
  FUN_800146a8();
  return;
}

