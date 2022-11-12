defmodule JasonEncoder do
  @moduledoc """
  Convenience module to pass to JOSE
  """

  def encode(term) do
    Jason.encode!(term)
  end

  def decode(string) do
    Jason.decode!(string)
  end
end
