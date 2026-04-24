// Function: FUN_8026cae4
// Entry: 8026cae4
// Size: 156 bytes

int FUN_8026cae4(int param_1)

{
  uint uVar1;
  undefined4 *puVar2;
  uint uVar3;
  undefined4 *puVar4;
  
LAB_8026caec:
  uVar1 = DAT_803deea8 + 1 & 0x7fffffff;
  for (puVar4 = DAT_803deeb4; puVar2 = DAT_803deeb0, uVar3 = DAT_803deea8,
      puVar4 != (undefined4 *)0x0; puVar4 = (undefined4 *)*puVar4) {
    if (puVar4[3] == DAT_803deea8) {
      uVar3 = 0xffffffff;
      break;
    }
  }
  do {
    if (puVar2 == (undefined4 *)0x0) break;
    if (puVar2[3] == uVar3) {
      uVar3 = 0xffffffff;
      break;
    }
    puVar2 = (undefined4 *)*puVar2;
  } while( true );
  DAT_803deea8 = uVar1;
  if (uVar3 != 0xffffffff) {
    *(uint *)(&DAT_803b15bc + param_1 * 0x1868) = uVar3;
    return uVar3;
  }
  goto LAB_8026caec;
}

