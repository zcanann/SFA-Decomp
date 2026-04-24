// Function: FUN_801db1f8
// Entry: 801db1f8
// Size: 268 bytes

void FUN_801db1f8(int param_1,undefined param_2)

{
  char cVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *(undefined *)(iVar2 + 0x1d) = param_2;
  cVar1 = *(char *)(iVar2 + 0x1d);
  if (cVar1 == '\x02') {
    *(undefined *)(iVar2 + 0x1d) = 0;
  }
  else if (cVar1 == '\x05') {
    FUN_800200e8(0x2b8,1);
    FUN_800200e8(0x4bd,0);
    FUN_800200e8(0x85,0);
    FUN_800146bc(0x1d,0x96);
    FUN_8000a518(0xef,1);
    FUN_8001469c();
  }
  else if (cVar1 == '\x03') {
    FUN_800146bc(0x1d,0x3c);
    *(undefined *)(iVar2 + 0x1d) = 0;
    FUN_8000a518(199,1);
    FUN_8001469c();
  }
  else if (cVar1 == '\x06') {
    FUN_8000a518(0xef,0);
    *(undefined *)(iVar2 + 0x1d) = 0;
    *(float *)(iVar2 + 0x14) = FLOAT_803e5550;
    FUN_8001467c();
  }
  else if (cVar1 == '\x04') {
    *(undefined *)(iVar2 + 0x1d) = 0;
    FUN_8000a518(199,0);
    FUN_8001467c();
  }
  return;
}

