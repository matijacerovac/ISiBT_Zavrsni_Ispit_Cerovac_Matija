// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Definiranje pametnog ugovora
contract Token {
    string public name = "Moj Token"; // Ime tokena
    string public symbol = "MT"; // Kratica tokena
    uint8 public decimals = 18; // Broj decimalnih mjesta

    // Ukupna količina tokena
    uint256 public totalSupply;

    // Stanje tokena za svaku adresu
    mapping(address => uint256) public balanceOf;

    // Vlasnik ugovora
    address public owner;

    // Događaj koji se emitira prilikom prijenosa tokena
    event Transfer(address indexed from, address indexed to, uint256 value);

    // Konstruktor ugovora
    constructor(uint256 _initialSupply) {
        totalSupply = _initialSupply; 
        balanceOf[msg.sender] = totalSupply;
        owner = msg.sender;
    }

    // Funkcija za prijenos tokena s jedne adrese na drugu
    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(_to != address(0), "Ne mozete slati token na adresu 0x0");
        require(balanceOf[msg.sender] >= _value, "Nemate dovoljno tokena na racunu");

        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    // Funkcija koja omogućuje vlasniku ugovora povećanje ukupne ponude tokena (mint)
    function mint(uint256 _value) public returns (bool success) {
        require(msg.sender == owner, "Samo vlasnik moze mjenjati ukupnu ponudu tokena");
        
        totalSupply += _value;
        balanceOf[msg.sender] += _value;
        emit Transfer(address(0), msg.sender, _value);
        return true;
    }

    // Funkcija koja omogućuje vlasniku ugovora smanjenje ukupne ponude tokena (burn)
    function burn(uint256 _value) public returns (bool success) {
        require(msg.sender == owner, "Samo vlasnik moze mjenjati ukupnu ponudu tokena");
        require(balanceOf[msg.sender] >= _value, "Nemate dovoljno tokena za spaljivanje");

        totalSupply -= _value;
        balanceOf[msg.sender] -= _value;
        emit Transfer(msg.sender, address(0), _value);
        return true;
    }
}
