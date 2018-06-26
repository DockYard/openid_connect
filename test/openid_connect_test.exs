defmodule OpenidConnectTest do
  use ExUnit.Case
  import Mox

  setup :set_mox_global
  setup :verify_on_exit!

  @google_document Fixtures.load(:google, :discovery_document)
  @google_certs Fixtures.load(:google, :certs)

  alias OpenidConnect.{HTTPClientMock}

  describe "update_documents" do
    test "when the new documents are retrieved successfully" do
      config = [
        discovery_document_uri: "https://accounts.google.com/.well-known/openid-configuration"
      ]

      HTTPClientMock
      |> expect(:get, fn "https://accounts.google.com/.well-known/openid-configuration" ->
        @google_document
      end)
      |> expect(:get, fn "https://www.googleapis.com/oauth2/v3/certs" -> @google_certs end)

      expected_document =
        @google_document
        |> elem(1)
        |> Map.get(:body)
        |> Jason.decode!()

      expected_certs =
        @google_certs
        |> elem(1)
        |> Map.get(:body)
        |> Jason.decode!()

      %{
        discovery_document: discovery_document,
        certs: certs,
        remaining_lifetime: remaining_lifetime
      } = OpenidConnect.update_documents(config)

      assert expected_document == discovery_document
      assert expected_certs == certs
      assert remaining_lifetime == 16750
    end
  end
end
