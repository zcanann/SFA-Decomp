// Function: FUN_801da284
// Entry: 801da284
// Size: 548 bytes

void FUN_801da284(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  char cVar4;
  undefined4 uVar2;
  int iVar3;
  int iVar5;
  undefined *puVar6;
  undefined *puVar7;
  
  iVar1 = FUN_802860d8();
  puVar6 = *(undefined **)(iVar1 + 0xb8);
  iVar5 = 0;
  puVar7 = puVar6;
  do {
    if (puVar6[iVar5 + 0x60] != '\0') {
      cVar4 = FUN_8002e04c();
      if (cVar4 == '\0') {
        uVar2 = 0;
      }
      else {
        iVar3 = FUN_8002bdf4(0x20,0x659);
        *(undefined *)(iVar3 + 4) = 2;
        *(undefined *)(iVar3 + 7) = 0xff;
        uVar2 = FUN_8002b5a0(iVar1);
      }
      *(undefined4 *)(puVar7 + 0x38) = uVar2;
      puVar6[iVar5 + 0x60] = 0;
    }
    puVar7 = puVar7 + 4;
    iVar5 = iVar5 + 1;
  } while (iVar5 < 10);
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar5 = iVar5 + 1) {
    switch(*(undefined *)(param_3 + iVar5 + 0x81)) {
    case 2:
      *puVar6 = 3;
      break;
    case 3:
      puVar6[1] = 1;
      break;
    case 4:
      puVar6[1] = 0;
      break;
    case 5:
      FUN_801da4a8(iVar1,puVar6,1);
      break;
    case 6:
      *puVar6 = 4;
      break;
    case 7:
      FUN_8011f38c(1);
      break;
    case 8:
      puVar6[2] = puVar6[2] | 1;
      break;
    case 9:
      puVar6[2] = puVar6[2] | 4;
      break;
    case 10:
      puVar6[2] = puVar6[2] | 0x10;
      *(float *)(puVar6 + 4) = FLOAT_803e54e0;
      break;
    case 0xb:
      puVar6[2] = puVar6[2] | 0x20;
      *(float *)(puVar6 + 4) = FLOAT_803e54d4;
      break;
    case 0xc:
      puVar6[2] = puVar6[2] | 0x10;
      puVar6[2] = puVar6[2] | 10;
      *(float *)(puVar6 + 4) = FLOAT_803e5508;
    }
  }
  if (puVar6[1] != '\0') {
    (**(code **)(*DAT_803dca68 + 0x34))((int)*(short *)(*(int *)(iVar1 + 0x50) + 0x7e),0xa0,0x8c);
  }
  *(float *)(puVar6 + 0x6c) = FLOAT_803e54d8 * FLOAT_803db414 + *(float *)(puVar6 + 0x6c);
  if (FLOAT_803e54d0 < *(float *)(puVar6 + 0x6c)) {
    *(float *)(puVar6 + 0x6c) = FLOAT_803e54d4;
  }
  FUN_80286124(0);
  return;
}

