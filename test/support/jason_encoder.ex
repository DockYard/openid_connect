defmodule JasonEncoder do
  def encode(term) do
    Jason.encode!(term)
  end

  def decode(string) do
    Jason.decode!(string)
  end
end
