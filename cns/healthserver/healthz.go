package healthserver

import (
	"fmt"
	"net/http"

	"github.com/Azure/azure-container-networking/cns"
	"github.com/Azure/azure-container-networking/cns/configuration"
	"github.com/Azure/azure-container-networking/crd/nodenetworkconfig/api/v1alpha"
	"github.com/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(v1alpha.AddToScheme(scheme))
}

func NewHealthzHandlerWithChecks(cnsConfig *configuration.CNSConfig) http.Handler {
	cfg, err := ctrl.GetConfig()
	if err != nil {
		panic(fmt.Errorf("unable to get config: %w", err))
	}
	cli, err := client.New(cfg, client.Options{
		Scheme: scheme,
	})
	if err != nil {
		panic(fmt.Errorf("unable to create client: %w", err))
	}

	checks := make(map[string]healthz.Checker)
	if cnsConfig.ChannelMode == cns.CRD {
		checks["nnc"] = func(req *http.Request) error {
			ctx := req.Context()
			// we just care that we're allowed to List NNCs so set limit to 1 to minimize
			// additional load on apiserver
			if err := cli.List(ctx, &v1alpha.NodeNetworkConfigList{}, &client.ListOptions{
				Namespace: metav1.NamespaceSystem,
				Limit:     int64(1),
			}); err != nil {
				return errors.Wrap(err, "failed to list NodeNetworkConfig")
			}
			return nil
		}
	}

	// strip prefix so that it runs through all checks registered on the handler.
	// otherwise it will look for a check named "healthz" and return a 404 if not there.
	return http.StripPrefix("/healthz", &healthz.Handler{
		Checks: checks,
	})
}
