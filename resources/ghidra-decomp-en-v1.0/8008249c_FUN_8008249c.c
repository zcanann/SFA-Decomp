// Function: FUN_8008249c
// Entry: 8008249c
// Size: 1588 bytes

/* WARNING: Removing unreachable block (ram,0x80082aa0) */
/* WARNING: Removing unreachable block (ram,0x80082a98) */
/* WARNING: Removing unreachable block (ram,0x80082aa8) */

void FUN_8008249c(void)

{
  short *psVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  undefined8 in_f29;
  double dVar4;
  undefined8 in_f30;
  double dVar5;
  undefined8 in_f31;
  double dVar6;
  undefined auStack424 [4];
  int local_1a4;
  undefined local_1a0;
  int local_19c;
  undefined local_198;
  float local_194;
  float local_190;
  undefined2 local_18c;
  short local_188;
  short local_186;
  short local_184;
  float local_17c;
  float local_178;
  float local_174;
  float local_170;
  float local_16c;
  float local_168;
  float local_d4;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar3 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  if (DAT_803dd0b8 == (short *)0x0) {
    if (DAT_803dd110 == '\0') {
      DAT_803dd108 = 1;
      DAT_803dd100 = 0x5a;
      DAT_803dd10c = 0x42;
    }
    else {
      if (DAT_803dd064 == 0) {
        switch(DAT_803dd10c) {
        case 0x44:
          if (DAT_803dd108 == 0) {
            local_194 = FLOAT_803deff4;
            local_190 = FLOAT_803deff8;
            local_18c = 0x1e;
            (**(code **)(*DAT_803dca50 + 0x1c))(0x44,1,0,0xc,&local_194,0,0xff);
          }
          else {
            local_194 = FLOAT_803deff4;
            local_190 = FLOAT_803deff8;
            local_18c = 5;
            (**(code **)(*DAT_803dca50 + 0x1c))(0x44,1,1,0xc,&local_194,0,0xff);
          }
          break;
        case 0x45:
          (**(code **)(*DAT_803dca50 + 0x1c))(0x45,1,0,0,0,DAT_803dd100,0xff);
          break;
        default:
          if (DAT_803dd108 == 0) {
            DAT_803dd108 = 1;
          }
          (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,DAT_803dd108,0,0,DAT_803dd100,0xff);
          break;
        case 0x47:
          local_19c = DAT_803dd108;
          local_198 = (undefined)DAT_803dd104;
          (**(code **)(*DAT_803dca50 + 0x1c))(0x47,1,3,8,&local_19c,DAT_803dd100,0xff);
          break;
        case 0x48:
          local_1a4 = DAT_803dd108;
          if (DAT_803dd100 == 0) {
            local_1a0 = 1;
          }
          (**(code **)(*DAT_803dca50 + 0x1c))(0x48,1,3,8,&local_1a4,DAT_803dd100,0xff);
          break;
        case 0x49:
          (**(code **)(*DAT_803dca50 + 0x1c))(0x49,1,0,DAT_803dd108,&DAT_803dd104,DAT_803dd100,0xff)
          ;
          break;
        case 0x4a:
          (**(code **)(*DAT_803dca50 + 0x1c))(0x4a,1,0,0,0,DAT_803dd100,0xff);
          break;
        case 0x4c:
          local_17c = FLOAT_803dd0b0;
          local_178 = FLOAT_803dd0ac;
          local_174 = FLOAT_803dd0a8;
          local_188 = (short)DAT_803dd0a0;
          local_186 = (short)DAT_803dd09c;
          local_184 = (short)DAT_803dd098;
          local_d4 = FLOAT_803dd0a4;
          (**(code **)(*DAT_803dca50 + 0x1c))(0x4c,1,0,0x144,&local_188,0,0xff);
          break;
        case 0x53:
          (**(code **)(*DAT_803dca50 + 0x1c))(0x53,1,0,0,0,0,0xff);
          break;
        case 0x56:
          (**(code **)(*DAT_803dca50 + 0x1c))(0x56,1,DAT_803dd108,0,0,0,0);
          break;
        case 0x57:
          (**(code **)(*DAT_803dca50 + 0x1c))(0x57,0,3,0,0,0,0);
          puVar2 = (undefined4 *)FUN_80036f50(0xf,auStack424);
          (**(code **)(*DAT_803dca50 + 0x28))(*puVar2,0);
        }
      }
      DAT_803dd110 = '\0';
      FLOAT_803db710 = FLOAT_803deffc;
      DAT_803dd108 = 1;
      DAT_803dd100 = 0x5a;
      DAT_803dd10c = 0x42;
      DAT_803dd08c = 0;
    }
  }
  else {
    local_168 = FLOAT_803dd0ec;
    local_16c = FLOAT_803dd0f0;
    local_170 = FLOAT_803dd0f4;
    if (DAT_803dd0f8 == '\0') {
      local_168 = *(float *)(DAT_803dd0b8 + 0x10);
      local_16c = *(float *)(DAT_803dd0b8 + 0xe);
      local_170 = *(float *)(DAT_803dd0b8 + 0xc);
    }
    dVar6 = (double)local_170;
    dVar5 = (double)local_16c;
    dVar4 = (double)local_168;
    local_188 = *DAT_803dd0b8;
    local_186 = DAT_803dd0b8[1];
    local_184 = DAT_803dd0b8[2];
    if (*(short **)(DAT_803dd0b8 + 0x18) != (short *)0x0) {
      local_188 = local_188 + **(short **)(DAT_803dd0b8 + 0x18);
    }
    FLOAT_803dd0dc = FLOAT_803defc8;
    if (DAT_803dd110 == '\0') {
      local_188 = -0x8000 - local_188;
      local_186 = -local_186;
      if (DAT_803dd088 == '\0') {
        local_d4 = FLOAT_803db710;
      }
      else {
        local_d4 = FLOAT_803dd0d0;
      }
      FLOAT_803db710 = local_d4;
      (**(code **)(*DAT_803dca50 + 0x1c))
                (0x4c,0,1,0x144,&local_188,*(undefined *)(*(int *)(DAT_803dd0b8 + 0x26) + 0x24),0xff
                );
      DAT_803dd110 = '\x01';
    }
    else {
      psVar1 = (short *)(**(code **)(*DAT_803dca50 + 0xc))();
      *(float *)(psVar1 + 0xc) = (float)dVar6;
      *(float *)(psVar1 + 0xe) = (float)dVar5;
      *(float *)(psVar1 + 0x10) = (float)dVar4;
      FUN_8000e034((double)*(float *)(psVar1 + 0xc),(double)*(float *)(psVar1 + 0xe),
                   (double)*(float *)(psVar1 + 0x10),psVar1 + 6,psVar1 + 8,psVar1 + 10,
                   *(undefined4 *)(psVar1 + 0x18));
      *psVar1 = -0x8000 - local_188;
      psVar1[1] = -local_186;
      psVar1[2] = local_184;
      if (DAT_803dd088 == '\0') {
        *(float *)(psVar1 + 0x5a) = FLOAT_803db710;
      }
      else {
        *(float *)(psVar1 + 0x5a) = FLOAT_803dd0d0;
        FLOAT_803db710 = FLOAT_803dd0d0;
      }
      FLOAT_803dd0b0 = *(float *)(psVar1 + 0xc);
      FLOAT_803dd0ac = *(float *)(psVar1 + 0xe);
      FLOAT_803dd0a8 = *(float *)(psVar1 + 0x10);
      DAT_803dd0a0 = (int)*psVar1;
      DAT_803dd09c = (int)psVar1[1];
      DAT_803dd098 = (int)psVar1[2];
      FLOAT_803dd0a4 = *(float *)(psVar1 + 0x5a);
    }
  }
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  __psq_l0(auStack24,uVar3);
  __psq_l1(auStack24,uVar3);
  __psq_l0(auStack40,uVar3);
  __psq_l1(auStack40,uVar3);
  DAT_803dd088 = 0;
  DAT_803dd0b8 = (short *)0x0;
  DAT_803dd0f8 = 0;
  return;
}

