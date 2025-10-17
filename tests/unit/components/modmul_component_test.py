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

import numpy as np
from claasp.cipher import Cipher
from claasp.name_mappings import BLOCK_CIPHER


def test_modmul_component_creation():
    """Test that MODMUL component can be created and has correct properties."""
    cipher = Cipher("test_modmul", BLOCK_CIPHER, ["input"], [32], 16)
    cipher.add_round()
    
    # Add MODMUL component with IDEA's modulus (2^16 + 1)
    modmul_component = cipher.add_MODMUL_component(
        ["input", "input"],
        [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
         [16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]],
        16,
        65537  # 2^16 + 1
    )
    
    assert modmul_component.id == "modmul_0_0"
    assert modmul_component.type == "word_operation"
    assert modmul_component.description[0] == "MODMUL"
    assert modmul_component.description[1] == 2  # number of inputs
    assert modmul_component.description[2] == 65537  # modulus
    assert modmul_component.output_bit_size == 16


def test_modmul_component_vectorized_code():
    """Test that MODMUL component generates correct vectorized code."""
    cipher = Cipher("test_modmul", BLOCK_CIPHER, ["input"], [32], 16)
    cipher.add_round()
    
    modmul_component = cipher.add_MODMUL_component(
        ["input", "input"],
        [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
         [16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]],
        16,
        65537
    )
    
    # Test bit-based vectorized code generation
    code = modmul_component.get_bit_based_vectorized_python_code(["a", "b"], False)
    assert len(code) == 1
    assert "bit_vector_MODMUL" in code[0]
    assert "modmul_0_0" in code[0]
    assert "65537" in code[0]


def test_modmul_idea_special_cases():
    """
    Test MODMUL with IDEA-specific test vectors.
    
    IDEA multiplication has special handling:
    - 0 is treated as 2^16 (65536)
    - Result 2^16 is mapped back to 0
    - Modulus is 2^16 + 1 (65537)
    """
    from claasp.cipher_modules.generic_functions_vectorized_bit import bit_vector_MODMUL
    
    word_size = 16
    modulus = 65537  # 2^16 + 1
    
    # Helper to convert integer to bit vector
    def int_to_bitvector(val, bits):
        arr = np.zeros((bits, 1), dtype=np.uint8)
        for i in range(bits):
            bit_position = bits - 1 - i
            arr[bit_position, 0] = (val >> i) & 1
        return arr
    
    # Helper to convert bit vector to integer
    def bitvector_to_int(arr):
        result = 0
        for i in range(len(arr)):
            bit_position = len(arr) - 1 - i
            result += arr[bit_position, 0] * (2**i)
        return result
    
    # Test Case 1: Normal multiplication
    # 3 * 5 mod 65537 = 15
    a1 = int_to_bitvector(3, word_size)
    b1 = int_to_bitvector(5, word_size)
    result1 = bit_vector_MODMUL([a1, b1], 2, word_size, modulus, verbosity=False)
    assert bitvector_to_int(result1) == 15, f"Expected 15, got {bitvector_to_int(result1)}"
    
    # Test Case 2: Multiplication with 0 (treated as 2^16)
    # 0 * 1 mod 65537 should be: (2^16 * 1) mod 65537 = 65536 mod 65537 = 65536
    # But 65536 maps back to 0
    a2 = int_to_bitvector(0, word_size)
    b2 = int_to_bitvector(1, word_size)
    result2 = bit_vector_MODMUL([a2, b2], 2, word_size, modulus, verbosity=False)
    assert bitvector_to_int(result2) == 0, f"Expected 0, got {bitvector_to_int(result2)}"
    
    # Test Case 3: Identity element
    # 1 is the multiplicative identity: 1 * x mod 65537 = x
    a3 = int_to_bitvector(1, word_size)
    b3 = int_to_bitvector(12345, word_size)
    result3 = bit_vector_MODMUL([a3, b3], 2, word_size, modulus, verbosity=False)
    assert bitvector_to_int(result3) == 12345, f"Expected 12345, got {bitvector_to_int(result3)}"
    
    # Test Case 4: Larger values
    # 1000 * 2000 mod 65537
    a4 = int_to_bitvector(1000, word_size)
    b4 = int_to_bitvector(2000, word_size)
    result4 = bit_vector_MODMUL([a4, b4], 2, word_size, modulus, verbosity=False)
    expected4 = (1000 * 2000) % modulus
    assert bitvector_to_int(result4) == expected4, f"Expected {expected4}, got {bitvector_to_int(result4)}"
    
    # Test Case 5: 0 * 0 should give 0
    # (2^16 * 2^16) mod 65537 = 4294967296 mod 65537 = 1
    # Wait, let me recalculate: (65536 * 65536) mod 65537
    # 65536 ≡ -1 (mod 65537), so (-1) * (-1) = 1
    a5 = int_to_bitvector(0, word_size)
    b5 = int_to_bitvector(0, word_size)
    result5 = bit_vector_MODMUL([a5, b5], 2, word_size, modulus, verbosity=False)
    # 0 -> 65536, so (65536 * 65536) mod 65537 = (2^32) mod 65537
    # We need to check: 2^32 mod 65537 = ?
    # 2^16 ≡ -1 (mod 65537), so 2^32 ≡ 1 (mod 65537)
    assert bitvector_to_int(result5) == 1, f"Expected 1, got {bitvector_to_int(result5)}"


def test_modmul_component_description():
    """Test that MODMUL component has correct description format."""
    cipher = Cipher("test_modmul", BLOCK_CIPHER, ["input"], [32], 16)
    cipher.add_round()
    
    modmul_component = cipher.add_MODMUL_component(
        ["input", "input"],
        [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
         [16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]],
        16,
        65537
    )
    
    # Description should be ['MODMUL', num_inputs, modulus]
    desc = modmul_component.description
    assert desc[0] == "MODMUL"
    assert desc[1] == 2
    assert desc[2] == 65537


def test_modmul_algebraic_polynomials():
    """Test that MODMUL component generates algebraic polynomials correctly."""
    from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
    
    cipher = Cipher("test_modmul", BLOCK_CIPHER, ["input"], [32], 16)
    cipher.add_round()
    
    modmul_component = cipher.add_MODMUL_component(
        ["input", "input"],
        [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
         [16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]],
        16,
        65537
    )
    
    algebraic = AlgebraicModel(cipher)
    polynomials = modmul_component.algebraic_polynomials(algebraic)
    
    # Check that polynomials were generated
    assert len(polynomials) > 0, "Should generate at least some polynomials"
    
    # Check that we have partial product polynomials (16*16 = 256 partial products)
    # Plus output constraints and carry initialization
    # Expected: 256 (partial products) + 16 (output constraints) + 1 (carry init) = 273
    assert len(polynomials) == 273, f"Expected 273 polynomials, got {len(polynomials)}"
    
    # Verify polynomial structure: check that first polynomial involves partial product variables
    poly_str = str(polynomials[0])
    assert "modmul_0_0" in poly_str, "Polynomials should reference component ID"
    
    # Check that partial product variables are present (format: modmul_0_0_p0_0, etc.)
    poly_vars = [str(p) for p in polynomials]
    has_partial_product = any("_p" in pv and "_" in pv for pv in poly_vars)
    assert has_partial_product, "Should have partial product variables"
    
    # Check carry initialization (first carry should be 0)
    # The carry initialization polynomial should be at index 256 + 16 = 272
    carry_init_poly = str(polynomials[-1])
    assert "carry_0" in carry_init_poly, "Last polynomial should initialize first carry"
