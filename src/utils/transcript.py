import base64

from .utils import mod_hash, point_to_b64


class Transcript:
    """
    Transcript class.
    Contains all parameters used to generate randomness using Fiat-Shamir
    Separate every entity by a '&'. 
    """

    def __init__(self, seed=b""):
        self.digest = base64.b64encode(seed) + b"&"

    def add_point(self, g):
        """Add an elliptic curve point to the transcript"""
        self.digest += point_to_b64(g)
        self.digest += b"&"

    def add_list_points(self, gs):
        """Add a list of elliptic curve point to the transcript"""
        for g in gs:
            self.add_point(g)

    def add_number(self, x):
        """Add a number to the transcript"""
        self.digest += str(x).encode()
        self.digest += b"&"

    def get_modp(self, p):
        """Generate a number as the hash of the digest"""
        return mod_hash(self.digest, p)
