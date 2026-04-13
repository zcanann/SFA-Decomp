// Function: FUN_8006ca98
// Entry: 8006ca98
// Size: 416 bytes

/* WARNING: Removing unreachable block (ram,0x8006cc20) */
/* WARNING: Removing unreachable block (ram,0x8006caa8) */

void FUN_8006ca98(void)

{
  uint uVar1;
  int iVar2;
  char cVar4;
  undefined *puVar3;
  double dVar5;
  double in_f31;
  double dVar6;
  double in_ps31_1;
  float local_28;
  float local_24;
  undefined8 local_20;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  iVar2 = FUN_80020800();
  if (iVar2 == 0) {
    FLOAT_803ddc2c = FLOAT_803dfa14 * FLOAT_803dc074 + FLOAT_803ddc2c;
    FLOAT_803ddc28 = FLOAT_803dfa18 * FLOAT_803dc074 + FLOAT_803ddc28;
    if (FLOAT_803dfa1c < FLOAT_803ddc2c) {
      FLOAT_803ddc2c = FLOAT_803ddc2c - FLOAT_803dfa1c;
    }
    if (FLOAT_803dfa1c < FLOAT_803ddc28) {
      FLOAT_803ddc28 = FLOAT_803ddc28 - FLOAT_803dfa1c;
    }
  }
  DAT_803ddbf8 = 0;
  DAT_803ddc68 = FUN_8000facc();
  DAT_803ddc20 = DAT_803ddc20 + (ushort)DAT_803dc070 * 0x28a;
  local_20 = CONCAT44(0x43300000,(uint)DAT_803ddc20);
  dVar5 = (double)FUN_802947f8();
  FLOAT_803ddc24 = (float)((double)FLOAT_803dfa20 * dVar5);
  FUN_80060d2c();
  DAT_803ddc0c = (char)(DAT_803ddc0c + 1) + (char)((DAT_803ddc0c + 1) / 3) * -3;
  cVar4 = FUN_8004c3c4();
  if (cVar4 != '\0') {
    puVar3 = FUN_8000f578();
    dVar6 = (double)*(float *)(puVar3 + 0x1c);
    FUN_8004c3b0(&local_24,&local_28);
    dVar5 = (double)local_24;
    if (dVar6 < dVar5) {
      if ((double)local_28 < dVar6) {
        uVar1 = (uint)((FLOAT_803df99c * (float)(dVar5 - dVar6)) / (float)(dVar5 - (double)local_28)
                      );
        local_20 = (longlong)(int)uVar1;
      }
      else {
        uVar1 = 0x40;
      }
    }
    else {
      uVar1 = 0;
    }
    if ((uVar1 & 0xff) != (uint)DAT_803ddc00) {
      FUN_8006a034(uVar1 & 0xff);
    }
  }
  return;
}

