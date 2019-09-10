/*********************************************************************
 *
 * AUTHORIZATION TO USE AND DISTRIBUTE
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: 
 *
 * (1) source code distributions retain this paragraph in its entirety, 
 *  
 * (2) distributions including binary code include this paragraph in
 *     its entirety in the documentation or other materials provided 
 *     with the distribution, and 
 *
 * (3) all advertising materials mentioning features or use of this 
 *     software display the following acknowledgment:
 * 
 *  The name of NRL, the name(s) of NRL  employee(s), or any entity
 *  of the United States Government may not be used to endorse or
 *  promote  products derived from this software, nor does the 
 *  inclusion of the NRL written and developed software  directly or
 *  indirectly suggest NRL or United States  Government endorsement
 *  of this product.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 * Revision history
 * Date  Author Details
 * 01/07/05 William Chao init version 
 * 01/07/05 Justin Dean init version
 * 03/14/05 Brian Adamson edits
 */

#include "protoBitmask.h"

class SmfSlidingWindow
{
    public:
        SmfSlidingWindow();
        ~SmfSlidingWindow();

        bool Init(UINT8     seqNumSize,  // in bits
                  UINT32    windowSize,  // in pkts
                  UINT32    windowPastMax); 
        
        void Destroy() {bitmask.Destroy();}
        
        bool IsDuplicate(UINT32 seqNum);

    private:
        ProtoSlidingMask bitmask;
        UINT32           window_past_max;
};  // end class SmfSlidingWindow

