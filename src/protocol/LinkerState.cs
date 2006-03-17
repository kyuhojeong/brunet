/*
This program is part of BruNet, a library for the creation of efficient overlay
networks.
Copyright (C) 2005  University of California
Copyright (C) 2005  P. Oscar Boykin <boykin@pobox.com>, University of Florida

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

using System;
using System.Collections;

/** The class maintains the state of linkers for an active connection attempt. */

namespace Brunet {
  public class LinkerState {
    /** list of remote TAs to work on. */
    protected ICollection target_list;
    
    /** number of pending linkers available. */
    protected int _count;

    /** accessor methods. */
    public int Count {
      get {
	return _count;
      }
      set {
	_count = value;
      }
    }
    public ICollection TAs {
      get {
	return target_list;
      }
      set {
	target_list = value;
      }
    }
    
    /** Constructor. */
    public LinkerState(ICollection tas) {
      target_list = tas;
      _count = 0;
    }
  }
}

