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

#include "smfWindow.h"

SmfSlidingWindow::SmfSlidingWindow()
{
}

SmfSlidingWindow::~SmfSlidingWindow()
{
    bitmask.Destroy();
}


bool SmfSlidingWindow::Init(UINT8  seqNumSize,   // in bits
                            UINT32 windowSize,   // in pkts
                            UINT32 windowPastMax)// in pkts
{
    // Make sure all parameters are valid
    if ((seqNumSize < 8) || (seqNumSize > 32))
    {
        PLOG(PL_ERROR, "SmfSlidingWindow::Init() error: invalid sequence number size: %d\n", seqNumSize);
        return false;
	}
       
    if (windowSize > ((UINT32)0x01 << (seqNumSize - 1)))
    {
        PLOG(PL_ERROR, "SmfSlidingWindow::Init() error: invalid windowSize\n");
        return false;
    }
    
    if ((windowPastMax < windowSize) ||
        (windowPastMax > ((UINT32)0x01 << (seqNumSize - 1))))
    {
        PLOG(PL_ERROR, "SmfSlidingWindow::Init() error: invalid windowPastMax value\n");
        return false;
    }
    
    // Note seqRangeMask == sequence value max 
    UINT32 seqRangeMask = 0xffffffff >> (32 - seqNumSize);
    if (!bitmask.Init(windowSize, seqRangeMask))
    {
        PLOG(PL_ERROR, "SmfSlidingWindow::Init() bitmask init error: %s\n",
                GetErrorString());
        return false;
    }
    
    window_past_max = windowPastMax;
    
    return true;
}  // end SmfSlidingWindow::Init()

bool SmfSlidingWindow::IsDuplicate(UINT32 seq)
{    
    // Get the "lastSet" sequence (our current window "middle")
    UINT32 lastSet;
    if (bitmask.GetLastSet(lastSet))
    {
        // What region does this "seq" fall into
        // with respect to our "window" ?
        INT32 rangeSign = (INT32)bitmask.GetRangeSign();
        INT32 rangeMask = (INT32)bitmask.GetRangeMask();
        INT32 delta = seq - lastSet;
        delta = ((0 == (delta & rangeSign)) ? 
                        (delta & rangeMask) :
                        (((delta != rangeSign) || (seq < lastSet)) ? 
                            (delta | ~rangeMask) : delta));
        if (delta > 0)
        {
            // It's a "new" packet 
            INT32 bitmaskSize = bitmask.GetSize();
            if (delta < bitmaskSize) // "slide" the window as needed
                bitmask.UnsetBits(lastSet - bitmaskSize + 1, delta);
            else  // It's beyond of our window range, so reset window
                bitmask.Clear();
            bitmask.Set(seq);
            return false;
        }
        else if (delta < 0)
        {
            // It's an "old" packet, so how old is it?
            delta = -delta;
            if (delta < bitmask.GetSize())
            {
                // It's old, but in our window ...
               if (bitmask.Test(seq))
                   return true;
               else
                   bitmask.Set(seq);
               return false;
            }
            else if (delta < (INT32)window_past_max)
            {
                // It's "very old", so assume it's a duplicate (but no reset)
                return true;   
            } 
            else
            {
                // It's so very "ancient", we reset our window to it
                PLOG(PL_ERROR, "SmfSlidingWindow::IsDuplicate() resetting window ...\n");
                bitmask.Clear();
                bitmask.Set(seq);
                return false;
            }
        }
        else
        {
            // It's a duplicate repeat of our lastSet
            return true;   
        }
    }
    else
    {
        // This is the first packet received  
        bitmask.Set(seq);
        return false;  // not a duplicate 
    }    
}  // end SmfSlidingWindow::IsDuplicate()
