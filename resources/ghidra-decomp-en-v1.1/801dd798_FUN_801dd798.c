// Function: FUN_801dd798
// Entry: 801dd798
// Size: 636 bytes

void FUN_801dd798(void)

{
  bool bVar1;
  undefined2 *puVar2;
  int iVar3;
  undefined4 *puVar4;
  int iVar5;
  undefined2 *puVar6;
  int iVar7;
  int iVar8;
  undefined8 uVar9;
  int local_48;
  int local_44;
  undefined auStack_40 [8];
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  undefined8 local_28;
  undefined8 local_20;
  
  uVar9 = FUN_80286840();
  puVar2 = (undefined2 *)((ulonglong)uVar9 >> 0x20);
  iVar5 = (int)uVar9;
  bVar1 = false;
  iVar8 = 0;
  iVar3 = FUN_8002e1f4(&local_44,&local_48);
  for (; local_44 < local_48; local_44 = local_44 + 1) {
    puVar6 = *(undefined2 **)(iVar3 + local_44 * 4);
    if (puVar6[0x23] == 0x3c1) {
      iVar7 = *(int *)(puVar6 + 0x5c);
      if ((*(ushort *)(iVar7 + 0x12) & 2) != 0) {
        if ((*(ushort *)(iVar7 + 0x12) & 1) == 0) {
          if (*(short *)(iVar7 + 0x10) == 4) {
            iVar8 = iVar8 + 1;
            if (puVar6 == puVar2) {
              local_20 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar5 + 0x10) ^ 0x80000000);
              *(float *)(iVar5 + 0xc) = FLOAT_803e6288 * (float)(local_20 - DOUBLE_803e62a8);
              local_28 = (double)(longlong)(int)*(float *)(iVar5 + 0xc);
              *puVar2 = (short)(int)*(float *)(iVar5 + 0xc);
              bVar1 = true;
            }
          }
          else if (puVar6 == puVar2) {
            FUN_8000bb38(0,0x487);
          }
        }
        else if (*(short *)(iVar7 + 0x10) == 3) {
          iVar8 = iVar8 + 1;
          if (puVar6 == puVar2) {
            local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar5 + 0x10) + 1U ^ 0x80000000);
            *(float *)(iVar5 + 0xc) = FLOAT_803e6288 * (float)(local_28 - DOUBLE_803e62a8);
            local_20 = (double)(longlong)(int)*(float *)(iVar5 + 0xc);
            *puVar2 = (short)(int)*(float *)(iVar5 + 0xc);
            bVar1 = true;
          }
        }
        else if (puVar6 == puVar2) {
          FUN_8000bb38(0,0x487);
        }
      }
    }
  }
  if (bVar1) {
    local_34 = FLOAT_803e628c;
    local_30 = FLOAT_803e6290;
    local_2c = FLOAT_803e628c;
    local_38 = FLOAT_803e6294;
    for (local_44 = 0x14; local_44 != 0; local_44 = local_44 + -1) {
      FUN_800979c0((double)FLOAT_803e6298,(double)FLOAT_803e629c,(double)FLOAT_803e629c,
                   (double)FLOAT_803e62a0,puVar2,7,5,7,100,(int)auStack_40,0);
    }
    puVar4 = (undefined4 *)FUN_800395a4((int)puVar2,0);
    if (puVar4 != (undefined4 *)0x0) {
      *puVar4 = 0x100;
    }
  }
  if (iVar8 == 5) {
    if (bVar1) {
      FUN_8000bb38(0,0x7e);
    }
  }
  else if (bVar1) {
    FUN_8000bb38(0,0x409);
  }
  FUN_8028688c();
  return;
}

