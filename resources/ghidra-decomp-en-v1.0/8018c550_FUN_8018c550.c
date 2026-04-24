// Function: FUN_8018c550
// Entry: 8018c550
// Size: 568 bytes

void FUN_8018c550(int param_1)

{
  float fVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined2 *puVar5;
  double dVar6;
  undefined auStack24 [4];
  int local_14;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  puVar5 = *(undefined2 **)(param_1 + 0xb8);
  iVar2 = FUN_8002b9ec();
  if ((*(byte *)(puVar5 + 0x2e) >> 6 & 1) == 0) {
    if ((*(short *)(iVar4 + 0x1e) == -1) || (iVar3 = FUN_8001ffb4(), iVar3 != 0)) {
      if ((char)*(byte *)(puVar5 + 0x2e) < '\0') {
        *(byte *)(puVar5 + 0x2e) = *(byte *)(puVar5 + 0x2e) & 0x7f;
        FUN_8000db90(param_1,0x403);
        FUN_80036fa4(param_1,0x4f);
      }
    }
    else if ((*(short *)(iVar4 + 0x20) == -1) || (iVar3 = FUN_8001ffb4(), iVar3 != 0)) {
      if ((char)*(byte *)(puVar5 + 0x2e) < '\0') {
        if ((*(byte *)(puVar5 + 0x2e) >> 4 & 1) != 0) {
          *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar4 + 8);
          *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar4 + 0xc);
          *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(iVar4 + 0x10);
          *(undefined *)(param_1 + 0x36) = 0xff;
          *(byte *)(puVar5 + 0x2e) = *(byte *)(puVar5 + 0x2e) & 0xef;
        }
      }
      else {
        FUN_8000dcbc(param_1,0x403);
        *(byte *)(puVar5 + 0x2e) = *(byte *)(puVar5 + 0x2e) & 0x7f | 0x80;
        FUN_80037200(param_1,0x4f);
      }
      fVar1 = *(float *)(param_1 + 0x10) - *(float *)(iVar2 + 0x10);
      if ((((FLOAT_803e3d08 < fVar1) && (fVar1 < FLOAT_803e3d0c)) &&
          (iVar4 = FUN_8001ffb4(0xe97), iVar4 == 0)) &&
         (dVar6 = (double)FUN_8002166c(param_1 + 0x18,iVar2 + 0x18), dVar6 < (double)FLOAT_803e3d10)
         ) {
        *puVar5 = 0xcbe;
        FUN_800378c4(iVar2,0x7000a,param_1,puVar5);
        *(byte *)(puVar5 + 0x2e) = *(byte *)(puVar5 + 0x2e) & 0xbf | 0x40;
        FUN_800200e8(0xe97,1);
        FUN_8000bb18(param_1,0x49);
      }
    }
  }
  else {
    while (iVar2 = FUN_800374ec(param_1,&local_14,auStack24,0), iVar2 != 0) {
      if (local_14 == 0x7000b) {
        *(byte *)(puVar5 + 0x2e) = *(byte *)(puVar5 + 0x2e) & 0xbf;
        FUN_800200e8((int)*(short *)(iVar4 + 0x1e),1);
        FUN_8001ff3c(0x3f5);
        FUN_800200e8(0xe97,0);
      }
    }
  }
  return;
}

