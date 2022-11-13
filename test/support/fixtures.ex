defmodule Fixtures do
  @moduledoc """
  Helpers for loading fixtures.

  TODO: Consider adding a mix task to rehydrate this from provided
  discovery_document_uris.
  """

  def load(provider, type) do
    response =
      Code.eval_file("test/fixtures/http/#{provider}/#{type}.exs")
      |> elem(0)
      |> serialize()

    {:ok, response}
  end

  defp serialize(%HTTPoison.Response{body: body} = response),
    do: %{response | body: Jason.encode!(body)}

  defp serialize(response), do: response
end
