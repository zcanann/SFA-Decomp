// Function: FUN_801dd1a8
// Entry: 801dd1a8
// Size: 636 bytes

void FUN_801dd1a8(void)

{
  bool bVar1;
  undefined2 *puVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 uVar5;
  int iVar6;
  undefined2 *puVar7;
  int iVar8;
  int iVar9;
  undefined8 uVar10;
  int local_48;
  int local_44;
  undefined auStack64 [8];
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  double local_28;
  double local_20;
  
  uVar10 = FUN_802860dc();
  puVar2 = (undefined2 *)((ulonglong)uVar10 >> 0x20);
  iVar6 = (int)uVar10;
  bVar1 = false;
  iVar9 = 0;
  iVar3 = FUN_8002e0fc(&local_44,&local_48);
  for (; local_44 < local_48; local_44 = local_44 + 1) {
    puVar7 = *(undefined2 **)(iVar3 + local_44 * 4);
    if (puVar7[0x23] == 0x3c1) {
      iVar8 = *(int *)(puVar7 + 0x5c);
      if ((*(ushort *)(iVar8 + 0x12) & 2) != 0) {
        if ((*(ushort *)(iVar8 + 0x12) & 1) == 0) {
          if (*(short *)(iVar8 + 0x10) == 4) {
            iVar9 = iVar9 + 1;
            if (puVar7 == puVar2) {
              local_20 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 0x10) ^ 0x80000000);
              *(float *)(iVar6 + 0xc) = FLOAT_803e55f0 * (float)(local_20 - DOUBLE_803e5610);
              local_28 = (double)(longlong)(int)*(float *)(iVar6 + 0xc);
              *puVar2 = (short)(int)*(float *)(iVar6 + 0xc);
              bVar1 = true;
            }
          }
          else if (puVar7 == puVar2) {
            FUN_8000bb18(0,0x487);
          }
        }
        else if (*(short *)(iVar8 + 0x10) == 3) {
          iVar9 = iVar9 + 1;
          if (puVar7 == puVar2) {
            local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 0x10) + 1U ^ 0x80000000);
            *(float *)(iVar6 + 0xc) = FLOAT_803e55f0 * (float)(local_28 - DOUBLE_803e5610);
            local_20 = (double)(longlong)(int)*(float *)(iVar6 + 0xc);
            *puVar2 = (short)(int)*(float *)(iVar6 + 0xc);
            bVar1 = true;
          }
        }
        else if (puVar7 == puVar2) {
          FUN_8000bb18(0,0x487);
        }
      }
    }
  }
  if (bVar1) {
    local_34 = FLOAT_803e55f4;
    local_30 = FLOAT_803e55f8;
    local_2c = FLOAT_803e55f4;
    local_38 = FLOAT_803e55fc;
    for (local_44 = 0x14; local_44 != 0; local_44 = local_44 + -1) {
      FUN_80097734((double)FLOAT_803e5600,(double)FLOAT_803e5604,(double)FLOAT_803e5604,
                   (double)FLOAT_803e5608,puVar2,7,5,7,100,auStack64,0);
    }
    puVar4 = (undefined4 *)FUN_800394ac(puVar2,0,0);
    if (puVar4 != (undefined4 *)0x0) {
      *puVar4 = 0x100;
    }
  }
  if (iVar9 == 5) {
    if (bVar1) {
      FUN_8000bb18(0,0x7e);
    }
    uVar5 = 1;
  }
  else {
    if (bVar1) {
      FUN_8000bb18(0,0x409);
    }
    uVar5 = 0;
  }
  FUN_80286128(uVar5);
  return;
}

