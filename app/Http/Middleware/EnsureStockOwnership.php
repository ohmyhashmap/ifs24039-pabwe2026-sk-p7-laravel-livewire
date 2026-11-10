<?php

namespace App\Http\Middleware;

use App\Features\Stock\Models\Stock;
use App\Models\User;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class EnsureStockOwnership
{
    /**
     * Handle an incoming request enforcing route-level ownership restrictions.
     *
     * @param  Closure(Request): (Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $currentUser = $request->user();

        if (! $currentUser) {
            abort(401, 'Unauthenticated');
        }

        // Check if route has {user} parameter
        $routeUser = $request->route('user');
        if ($routeUser) {
            $targetUserId = $routeUser instanceof User ? $routeUser->id : (int) $routeUser;

            if ($currentUser->isMember() && $currentUser->id !== $targetUserId) {
                abort(403, 'Akses ditolak: Member tidak dapat mengakses stok barang orang lain.');
            }
        }

        // Stock detail pages are readable by any authenticated user, but writes remain owner-only.
        $routeStock = $request->route('stock');
        if ($routeStock) {
            $stock = $routeStock instanceof Stock ? $routeStock : Stock::find($routeStock);

            if ($stock && $request->isMethodSafe() === false && $currentUser->id !== $stock->user_id) {
                abort(403, 'Akses ditolak: Hanya pemilik stok barang yang dapat mengubah data ini.');
            }
        }

        return $next($request);
    }
}
