; Original address was $B28B
; World 3's Big [?] block area
    .word $0000 ; Alternate level layout
    .word $0000 ; Alternate object layout
    .byte LEVEL1_SIZE_08 | LEVEL1_YSTART_170
    .byte LEVEL2_BGPAL_03 | LEVEL2_OBJPAL_08 | LEVEL2_XSTART_18
    .byte LEVEL3_TILESET_03 | LEVEL3_VSCROLL_FREE
    .byte 3 & %00011111 | LEVEL4_INITACT_NOTHING
    .byte LEVEL5_BGM_UNDERGROUND | LEVEL5_TIME_300

    .byte $40, $00, $0E, $40, $10, $B1, $03, $42, $10, $BF, $00, $52, $10, $B6, $00, $59
    .byte $10, $B1, $0F, $40, $14, $BF, $0B, $50, $1F, $B8, $00, $20, $11, $D1, $30, $1D
    .byte $C5, $24, $12, $80, $25, $11, $80, $26, $12, $80, $27, $11, $80, $28, $12, $80
    .byte $29, $11, $80, $2A, $12, $80, $2B, $11, $80, $2C, $12, $80, $40, $40, $BF, $00
    .byte $50, $40, $B8, $00, $59, $40, $B1, $0F, $57, $47, $B1, $08, $45, $4F, $BF, $00
    .byte $55, $4F, $B1, $00, $40, $48, $B4, $07, $40, $43, $B6, $04, $4B, $43, $B6, $02
    .byte $4D, $46, $B4, $05, $20, $41, $D1, $35, $4C, $E2, $24, $41, $80, $25, $42, $80
    .byte $26, $41, $80, $27, $42, $80, $28, $41, $80, $29, $42, $80, $2A, $41, $80, $2B
    .byte $42, $80, $2C, $41, $80, $2D, $42, $80, $40, $50, $BF, $00, $50, $50, $B8, $00
    .byte $59, $50, $B1, $0F, $57, $57, $B1, $08, $45, $5F, $BF, $00, $55, $5F, $B1, $00
    .byte $40, $58, $B4, $07, $40, $53, $B6, $04, $4B, $53, $B6, $02, $4D, $56, $B4, $05
    .byte $20, $51, $D1, $35, $5C, $E2, $24, $51, $80, $25, $52, $80, $26, $51, $80, $27
    .byte $52, $80, $28, $51, $80, $29, $52, $80, $2A, $51, $80, $2B, $52, $80, $2C, $51
    .byte $80, $2D, $52, $80, $E1, $00, $00, $E4, $71, $46, $E5, $61, $76, $FF
