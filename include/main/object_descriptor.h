#ifndef MAIN_OBJECT_DESCRIPTOR_H_
#define MAIN_OBJECT_DESCRIPTOR_H_

#include "ghidra_import.h"

typedef void (*ObjectDescriptorCallback)(void);
typedef int (*ObjectDescriptorExtraSizeCallback)(void);

typedef struct ObjectDescriptor {
  u32 reserved0;
  u32 reserved1;
  u32 reserved2;
  u32 slotCountAndFlags;
  ObjectDescriptorCallback initialise;
  ObjectDescriptorCallback release;
  ObjectDescriptorCallback slot02;
  ObjectDescriptorCallback init;
  ObjectDescriptorCallback update;
  ObjectDescriptorCallback hitDetect;
  ObjectDescriptorCallback render;
  ObjectDescriptorCallback free;
  ObjectDescriptorCallback slot08;
  ObjectDescriptorExtraSizeCallback getExtraSize;
} ObjectDescriptor;

typedef struct ObjectDescriptor11 {
  u32 reserved0;
  u32 reserved1;
  u32 reserved2;
  u32 slotCountAndFlags;
  ObjectDescriptorCallback initialise;
  ObjectDescriptorCallback release;
  ObjectDescriptorCallback slot02;
  ObjectDescriptorCallback init;
  ObjectDescriptorCallback update;
  ObjectDescriptorCallback hitDetect;
  ObjectDescriptorCallback render;
  ObjectDescriptorCallback free;
  ObjectDescriptorCallback slot08;
  ObjectDescriptorCallback slot09;
  ObjectDescriptorCallback slot0A;
} ObjectDescriptor11;

typedef struct ObjectDescriptor10WithPadding {
  ObjectDescriptor descriptor;
  u32 padding;
} ObjectDescriptor10WithPadding;

typedef struct ObjectDescriptor11ExtraSize {
  u32 reserved0;
  u32 reserved1;
  u32 reserved2;
  u32 slotCountAndFlags;
  ObjectDescriptorCallback initialise;
  ObjectDescriptorCallback release;
  ObjectDescriptorCallback slot02;
  ObjectDescriptorCallback init;
  ObjectDescriptorCallback update;
  ObjectDescriptorCallback hitDetect;
  ObjectDescriptorCallback render;
  ObjectDescriptorCallback free;
  ObjectDescriptorCallback slot08;
  ObjectDescriptorExtraSizeCallback getExtraSize;
  ObjectDescriptorCallback slot0A;
} ObjectDescriptor11ExtraSize;

typedef struct ObjectDescriptor11WithPadding {
  ObjectDescriptor11ExtraSize descriptor;
  u32 padding;
} ObjectDescriptor11WithPadding;

typedef struct ObjectDescriptor12 {
  u32 reserved0;
  u32 reserved1;
  u32 reserved2;
  u32 slotCountAndFlags;
  ObjectDescriptorCallback initialise;
  ObjectDescriptorCallback release;
  ObjectDescriptorCallback slot02;
  ObjectDescriptorCallback init;
  ObjectDescriptorCallback update;
  ObjectDescriptorCallback hitDetect;
  ObjectDescriptorCallback render;
  ObjectDescriptorCallback free;
  ObjectDescriptorCallback slot08;
  ObjectDescriptorExtraSizeCallback getExtraSize;
  ObjectDescriptorCallback slot0A;
  ObjectDescriptorCallback slot0B;
} ObjectDescriptor12;

typedef struct ObjectDescriptor13 {
  u32 reserved0;
  u32 reserved1;
  u32 reserved2;
  u32 slotCountAndFlags;
  ObjectDescriptorCallback initialise;
  ObjectDescriptorCallback release;
  ObjectDescriptorCallback slot02;
  ObjectDescriptorCallback init;
  ObjectDescriptorCallback update;
  ObjectDescriptorCallback hitDetect;
  ObjectDescriptorCallback render;
  ObjectDescriptorCallback free;
  ObjectDescriptorCallback slot08;
  ObjectDescriptorExtraSizeCallback getExtraSize;
  ObjectDescriptorCallback slot0A;
  ObjectDescriptorCallback slot0B;
  ObjectDescriptorCallback slot0C;
} ObjectDescriptor13;

typedef struct ObjectDescriptor14 {
  u32 reserved0;
  u32 reserved1;
  u32 reserved2;
  u32 slotCountAndFlags;
  ObjectDescriptorCallback initialise;
  ObjectDescriptorCallback release;
  ObjectDescriptorCallback slot02;
  ObjectDescriptorCallback init;
  ObjectDescriptorCallback update;
  ObjectDescriptorCallback hitDetect;
  ObjectDescriptorCallback render;
  ObjectDescriptorCallback free;
  ObjectDescriptorCallback slot08;
  ObjectDescriptorCallback slot09;
  ObjectDescriptorCallback slot0A;
  ObjectDescriptorCallback slot0B;
  ObjectDescriptorCallback slot0C;
  ObjectDescriptorCallback slot0D;
} ObjectDescriptor14;

typedef struct ObjectDescriptor15 {
  u32 reserved0;
  u32 reserved1;
  u32 reserved2;
  u32 slotCountAndFlags;
  ObjectDescriptorCallback initialise;
  ObjectDescriptorCallback release;
  ObjectDescriptorCallback slot02;
  ObjectDescriptorCallback init;
  ObjectDescriptorCallback update;
  ObjectDescriptorCallback hitDetect;
  ObjectDescriptorCallback render;
  ObjectDescriptorCallback free;
  ObjectDescriptorCallback slot08;
  ObjectDescriptorExtraSizeCallback getExtraSize;
  ObjectDescriptorCallback slot0A;
  ObjectDescriptorCallback slot0B;
  ObjectDescriptorCallback slot0C;
  ObjectDescriptorCallback slot0D;
  ObjectDescriptorCallback slot0E;
} ObjectDescriptor15;

typedef struct ObjectDescriptor16 {
  u32 reserved0;
  u32 reserved1;
  u32 reserved2;
  u32 slotCountAndFlags;
  ObjectDescriptorCallback initialise;
  ObjectDescriptorCallback release;
  ObjectDescriptorCallback slot02;
  ObjectDescriptorCallback init;
  ObjectDescriptorCallback update;
  ObjectDescriptorCallback hitDetect;
  ObjectDescriptorCallback render;
  ObjectDescriptorCallback free;
  ObjectDescriptorCallback slot08;
  ObjectDescriptorExtraSizeCallback getExtraSize;
  ObjectDescriptorCallback slot0A;
  ObjectDescriptorCallback slot0B;
  ObjectDescriptorCallback slot0C;
  ObjectDescriptorCallback slot0D;
  ObjectDescriptorCallback slot0E;
  ObjectDescriptorCallback slot0F;
} ObjectDescriptor16;

typedef struct ObjectDescriptor16WithPadding {
  ObjectDescriptor16 descriptor;
  u32 padding;
} ObjectDescriptor16WithPadding;

typedef struct ObjectDescriptor17 {
  u32 reserved0;
  u32 reserved1;
  u32 reserved2;
  u32 slotCountAndFlags;
  ObjectDescriptorCallback initialise;
  ObjectDescriptorCallback release;
  ObjectDescriptorCallback slot02;
  ObjectDescriptorCallback init;
  ObjectDescriptorCallback update;
  ObjectDescriptorCallback hitDetect;
  ObjectDescriptorCallback render;
  ObjectDescriptorCallback free;
  ObjectDescriptorCallback slot08;
  ObjectDescriptorExtraSizeCallback getExtraSize;
  ObjectDescriptorCallback slot0A;
  ObjectDescriptorCallback slot0B;
  ObjectDescriptorCallback slot0C;
  ObjectDescriptorCallback slot0D;
  ObjectDescriptorCallback slot0E;
  ObjectDescriptorCallback slot0F;
  ObjectDescriptorCallback slot10;
} ObjectDescriptor17;

typedef struct ObjectDescriptor20 {
  u32 reserved0;
  u32 reserved1;
  u32 reserved2;
  u32 slotCountAndFlags;
  ObjectDescriptorCallback initialise;
  ObjectDescriptorCallback release;
  ObjectDescriptorCallback slot02;
  ObjectDescriptorCallback init;
  ObjectDescriptorCallback update;
  ObjectDescriptorCallback hitDetect;
  ObjectDescriptorCallback render;
  ObjectDescriptorCallback free;
  ObjectDescriptorCallback slot08;
  ObjectDescriptorExtraSizeCallback getExtraSize;
  ObjectDescriptorCallback slot0A;
  ObjectDescriptorCallback slot0B;
  ObjectDescriptorCallback slot0C;
  ObjectDescriptorCallback slot0D;
  ObjectDescriptorCallback slot0E;
  ObjectDescriptorCallback slot0F;
  ObjectDescriptorCallback slot10;
  ObjectDescriptorCallback slot11;
  ObjectDescriptorCallback slot12;
  ObjectDescriptorCallback slot13;
} ObjectDescriptor20;

typedef struct ObjectDescriptor23 {
  u32 reserved0;
  u32 reserved1;
  u32 reserved2;
  u32 slotCountAndFlags;
  ObjectDescriptorCallback initialise;
  ObjectDescriptorCallback release;
  ObjectDescriptorCallback slot02;
  ObjectDescriptorCallback init;
  ObjectDescriptorCallback update;
  ObjectDescriptorCallback hitDetect;
  ObjectDescriptorCallback render;
  ObjectDescriptorCallback free;
  ObjectDescriptorCallback slot08;
  ObjectDescriptorExtraSizeCallback getExtraSize;
  ObjectDescriptorCallback slot0A;
  ObjectDescriptorCallback slot0B;
  ObjectDescriptorCallback slot0C;
  ObjectDescriptorCallback slot0D;
  ObjectDescriptorCallback slot0E;
  ObjectDescriptorCallback slot0F;
  ObjectDescriptorCallback slot10;
  ObjectDescriptorCallback slot11;
  ObjectDescriptorCallback slot12;
  ObjectDescriptorCallback slot13;
  ObjectDescriptorCallback slot14;
  ObjectDescriptorCallback slot15;
  ObjectDescriptorCallback slot16;
} ObjectDescriptor23;

#define OBJECT_DESCRIPTOR_FLAGS_10_SLOTS 0x00090000
#define OBJECT_DESCRIPTOR_FLAGS_11_SLOTS 0x000A0000
#define OBJECT_DESCRIPTOR_FLAGS_12_SLOTS 0x000B0000
#define OBJECT_DESCRIPTOR_FLAGS_13_SLOTS 0x000C0000
#define OBJECT_DESCRIPTOR_FLAGS_14_SLOTS 0x000D0000
#define OBJECT_DESCRIPTOR_FLAGS_15_SLOTS 0x000E0000
#define OBJECT_DESCRIPTOR_FLAGS_16_SLOTS 0x000F0000
#define OBJECT_DESCRIPTOR_FLAGS_17_SLOTS 0x00100000
#define OBJECT_DESCRIPTOR_FLAGS_20_SLOTS 0x00130000
#define OBJECT_DESCRIPTOR_FLAGS_23_SLOTS 0x00160000

#endif /* MAIN_OBJECT_DESCRIPTOR_H_ */
