// Function: FUN_8002b554
// Entry: 8002b554
// Size: 268 bytes

/* WARNING: Removing unreachable block (ram,0x8002b63c) */
/* WARNING: Removing unreachable block (ram,0x8002b564) */

void FUN_8002b554(ushort *param_1,float *param_2,char param_3)

{
  double in_f31;
  float afStack_68 [19];
  
  if (*(int *)(param_1 + 0x18) == 0) {
    *(float *)(param_1 + 6) = *(float *)(param_1 + 6) - FLOAT_803dda58;
    *(float *)(param_1 + 10) = *(float *)(param_1 + 10) - FLOAT_803dda5c;
  }
  if ((param_3 != '\0') && (in_f31 = (double)*(float *)(param_1 + 4), (param_1[0x58] & 8) == 0)) {
    *(float *)(param_1 + 4) = FLOAT_803df510;
  }
  FUN_80021634(param_1,param_2);
  if (param_3 != '\0') {
    *(float *)(param_1 + 4) = (float)in_f31;
  }
  if (*(ushort **)(param_1 + 0x18) == (ushort *)0x0) {
    *(float *)(param_1 + 6) = *(float *)(param_1 + 6) + FLOAT_803dda58;
    *(float *)(param_1 + 10) = *(float *)(param_1 + 10) + FLOAT_803dda5c;
  }
  else {
    FUN_8002b554(*(ushort **)(param_1 + 0x18),afStack_68,'\x01');
    FUN_80247618(afStack_68,param_2,param_2);
  }
  return;
}

