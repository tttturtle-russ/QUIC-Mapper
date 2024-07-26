# -*- coding: utf-8 -*-

# +---------------------------------------------------------------------------+
# | pylstar : Implementation of the LSTAR Grammatical Inference Algorithm     |
# +---------------------------------------------------------------------------+
# | Copyright (C) 2015 Georges Bossert                                        |
# | This program is free software: you can redistribute it and/or modify      |
# | it under the terms of the GNU General Public License as published by      |
# | the Free Software Foundation, either version 3 of the License, or         |
# | (at your option) any later version.                                       |
# |                                                                           |
# | This program is distributed in the hope that it will be useful,           |
# | but WITHOUT ANY WARRANTY; without even the implied warranty of            |
# | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the              |
# | GNU General Public License for more details.                              |
# |                                                                           |
# | You should have received a copy of the GNU General Public License         |
# | along with this program. If not, see <http://www.gnu.org/licenses/>.      |
# +---------------------------------------------------------------------------+
# | @url      : https://github.com/gbossert/pylstar                           |
# | @contact  : gbossert@miskin.fr                                            |
# +---------------------------------------------------------------------------+

# +----------------------------------------------------------------------------
# | Global Imports
# +----------------------------------------------------------------------------


# +----------------------------------------------------------------------------
# | Pylstar Imports
# +----------------------------------------------------------------------------
from pylstar.tools.Decorators import PylstarLogger


@PylstarLogger
class Transition(object):
    """Definition of a transition that belongs to an automata
    """

    def __init__(self, name, output_state, input_letter, output_letter):
        self.name = name
        self.output_state = output_state
        self.input_letter = input_letter
        self.output_letter = output_letter

    @property
    def label(self):
        input_symbols = []
        for symbol in self.input_letter.symbols:
            try:
                input_symbols.append(symbol.name)
            except Exception:
                input_symbols.append(str(symbol))

        output_symbols = []
        for symbol in self.output_letter.symbols:
            try:
                output_symbols.append(symbol.name)
            except Exception:
                output_symbols.append(str(symbol))
        
        return "{} / {}".format(",".join(input_symbols), ",".join(output_symbols))

        
        

        

    
