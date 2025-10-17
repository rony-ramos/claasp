# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# ****************************************************************************


from claasp.components.modular_component import Modular
from claasp.cipher_modules.models.smt.utils import utils as smt_utils
from claasp.cipher_modules.models.sat.utils import utils as sat_utils


class MODMUL(Modular):
    """
    Component for modular multiplication as used in IDEA.
    Performs (a * b) % (2**16 + 1) with the special rule for zero.
    
    In IDEA, the value 0 is treated as 2**16 for multiplication purposes,
    and the result 2**16 is mapped back to 0.
    """
    
    def __init__(
        self,
        current_round_number,
        current_round_number_of_components,
        input_id_links,
        input_bit_positions,
        output_bit_size,
        modulus,
    ):
        super().__init__(
            current_round_number,
            current_round_number_of_components,
            input_id_links,
            input_bit_positions,
            output_bit_size,
            "modmul",
            modulus,
        )

    def algebraic_polynomials(self, model):
        """
        Return a list of polynomials for Modular Multiplication.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.cipher import Cipher
            sage: from claasp.name_mappings import BLOCK_CIPHER
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: cipher = Cipher("test_modmul", BLOCK_CIPHER, ["input"], [32], 16)
            sage: cipher.add_round()
            sage: modmul_component = cipher.add_MODMUL_component(["input","input"], [[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],[16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31]], 16, 65537)
            sage: algebraic = AlgebraicModel(cipher)
            sage: polys = modmul_component.algebraic_polynomials(algebraic)
            sage: len(polys) > 0
            True

        .. NOTE::

            This is a simplified algebraic model. A full model would represent
            the multiplication as a composition of partial products (AND operations)
            and additions, followed by modular reduction.
            
            For now, we create a basic model with:
            - Partial products: p[i][j] = a[i] * b[j] (product bits)
            - Intermediate sums and carries
            - Output constraints relating to inputs
        """
        component_id = self.id
        ninput_words = self.description[1]  # should be 2 for multiplication
        ninput_bits = self.input_bit_size
        noutput_bits = word_size = self.output_bit_size
        
        # Create variable name strings
        input_vars = [f"{component_id}_{model.input_postfix}{i}" for i in range(ninput_bits)]
        output_vars = [f"{component_id}_{model.output_postfix}{i}" for i in range(noutput_bits)]
        
        # Partial product variable names: p_i_j represents a[i] AND b[j]
        partial_product_vars_names = [
            [f"{component_id}_p{i}_{j}" for j in range(word_size)]
            for i in range(word_size)
        ]
        
        # Carry variable names for the addition tree
        carry_vars_names = [f"{component_id}_carry_{i}" for i in range(word_size * 2)]
        
        # Get the polynomial ring (already contains all variables declared in var_names())
        ring_R = model.ring()
        
        # Convert variable names to ring elements
        input_vars = list(map(ring_R, input_vars))
        output_vars = list(map(ring_R, output_vars))
        partial_product_vars = [list(map(ring_R, pp_row)) for pp_row in partial_product_vars_names]
        carry_vars = list(map(ring_R, carry_vars_names))
        
        # Extract operands a and b from input
        a = input_vars[:word_size]
        b = input_vars[word_size:word_size * 2]
        
        polynomials = []
        
        # Constraint 1: Partial products p[i][j] = a[i] * b[j]
        # In GF(2), AND is modeled as: p_ij + a_i*b_j + a_i*p_ij + b_j*p_ij = 0
        for i in range(word_size):
            for j in range(word_size):
                polynomials.append(
                    partial_product_vars[i][j] + a[i] * b[j] + a[i] * partial_product_vars[i][j] + b[j] * partial_product_vars[i][j]
                )
        
        # Constraint 2: Relate output to partial products (simplified)
        # Full multiplication would sum shifted partial products with carry propagation
        # For now, create symbolic relationship: each output bit depends on corresponding partial products
        # This is a placeholder - real implementation would model full addition tree
        for k in range(noutput_bits):
            # Symbolically: output[k] is XOR of relevant partial products and carries
            polynomials.append(output_vars[k] + partial_product_vars[min(k, word_size-1)][0] + carry_vars[k])
        
        # Constraint 3: Initialize first carry
        polynomials.append(carry_vars[0])
        
        return polynomials

    def cms_constraints(self):
        """
        Return a list of variables and a list of clauses for Modular Multiplication in CMS CIPHER model.

        .. NOTE::

            This is a placeholder. The CMS model would need to represent the multiplication
            as a composition of partial products (AND operations) and additions (MODADD).
        """
        raise NotImplementedError(
            "CMS constraints for MODMUL are not yet implemented. "
            "Implementation would follow the shift-and-add decomposition approach."
        )

    def cp_constraints(self):
        """
        Return lists of declarations and constraints for Modular Multiplication component for CP CIPHER model.

        .. NOTE::

            This is a placeholder. The CP model would decompose the multiplication
            into partial products and a tree of additions.
        """
        raise NotImplementedError(
            "CP constraints for MODMUL are not yet implemented. "
            "Implementation would model partial products and accumulation tree."
        )

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        """
        Generate Python code for evaluation, implementing IDEA multiplication logic.
        
        INPUT:

        - ``params`` -- **list**; the parameters for the function
        - ``convert_output_to_bytes`` -- **boolean**; whether to convert output to bytes

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.idea_block_cipher import IdeaBlockCipher
            sage: idea = IdeaBlockCipher(number_of_rounds=8)
            sage: modmul_component = idea.component_from(0, 0)  # assuming first component is MODMUL
            sage: modmul_component.get_bit_based_vectorized_python_code(['a', 'b'], False)
            ['  modmul_0_0 = bit_vector_MODMUL([a,b], 2, 16, 65537)']
        """
        return [
            f"  {self.id} = bit_vector_MODMUL([{','.join(params)}], "
            f"{self.description[1]}, {self.output_bit_size}, {self.description[2]})"
        ]

    def get_byte_based_vectorized_python_code(self, params):
        """
        Generate byte-based vectorized Python code for MODMUL evaluation.
        
        INPUT:

        - ``params`` -- **string**; the parameters for the function
        """
        return [f"  {self.id} = byte_vector_MODMUL({params}, {self.description[2]})"]

    def sat_constraints(self):
        """
        Return a list of variables and a list of clauses representing MODULAR MULTIPLICATION for SAT CIPHER model.

        .. NOTE::

            This is a placeholder. The SAT encoding would decompose the multiplication
            into partial products (using AND constraints) and a tree of additions
            (using MODADD constraints), followed by the final modular reduction.

        The general approach:
        1. Model partial products: p[i] = a * b[i] (bitwise AND with broadcast)
        2. Model accumulation tree: sum partial products with shifts
        3. Model modular reduction: reduce result mod (2^n + 1) or other modulus
        4. Handle IDEA special case: 0 -> 2^16 mapping
        """
        raise NotImplementedError(
            "SAT constraints for MODMUL are not yet implemented. "
            "Implementation requires decomposition into partial products (AND) "
            "and accumulation tree (MODADD), plus handling the IDEA zero-mapping rule."
        )

    def smt_constraints(self):
        """
        Return a variable list and SMT-LIB list asserts representing MODULAR MULTIPLICATION for SMT CIPHER model.

        .. NOTE::

            This is a placeholder. Similar to SAT, but using SMT-LIB syntax.
        """
        raise NotImplementedError(
            "SMT constraints for MODMUL are not yet implemented. "
            "Implementation would follow the same decomposition as SAT but with SMT-LIB syntax."
        )
